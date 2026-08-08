/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.thoughtcrime.securesms.registration.ui.restore

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.signal.core.util.logging.Log
import org.signal.libsignal.protocol.IdentityKeyPair
import org.signal.registration.proto.RegistrationProvisionMessage
import org.thoughtcrime.securesms.backup.v2.MessageBackupTier
import org.thoughtcrime.securesms.components.settings.app.usernamelinks.QrCodeData
import org.thoughtcrime.securesms.dependencies.AppDependencies
import org.thoughtcrime.securesms.keyvalue.SignalStore
import org.thoughtcrime.securesms.registration.data.network.RegisterAccountResult
import org.whispersystems.signalservice.api.provisioning.ProvisioningSocket
import org.whispersystems.signalservice.internal.crypto.SecondaryProvisioningCipher
import java.io.Closeable
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

class RestoreViaQrViewModel : ViewModel() {

  companion object {
    private val TAG = Log.tag(RestoreViaQrViewModel::class)

    /** Number of consecutive connection failures to tolerate before telling the user something is wrong. Reconnecting continues regardless. */
    private const val FAILURES_BEFORE_ERROR = 3

    private val MIN_RECONNECT_DELAY = 1.seconds
    private val MAX_RECONNECT_DELAY = 30.seconds
  }

  private val store: MutableStateFlow<RestoreViaQrState> = MutableStateFlow(RestoreViaQrState())

  val state: StateFlow<RestoreViaQrState> = store

  private var socketHandles: MutableList<Closeable> = mutableListOf()
  private var startNewSocketJob: Job? = null

  private val consecutiveFailures = AtomicInteger(0)

  /** Wakes the socket loop early, either because the socket behind the visible QR code died or because the screen came back. */
  private val reconnectNow = Channel<Unit>(Channel.CONFLATED)

  init {
    restart()
  }

  fun restart() {
    SignalStore.registration.restoreMethodToken = null
    shutdown()

    consecutiveFailures.set(0)
    reconnectNow.tryReceive()
    store.update { it.copy(currentSocketId = null, qrState = QrState.Loading) }

    startNewSocketJob = viewModelScope.launch(Dispatchers.IO) {
      while (isActive) {
        startNewSocket()

        // MOLLY: Wait until a new socket is genuinely needed rather than rotating on a timer. Only a failure
        // that happens before any QR code reaches the screen asks for one, so a displayed code is never
        // swapped out from under the user.
        reconnectNow.receive()

        val failures = consecutiveFailures.get()
        if (failures > 0) {
          delay(reconnectDelay(failures))
        }
      }
    }
  }

  /**
   * Called when the screen becomes visible again. Only useful when the first connection never produced a code, e.g.
   * the screen was opened while offline.
   *
   * MOLLY: A code that is already displayed is deliberately left alone, even though its socket may be long dead, so
   * that toggling Wi-Fi or switching users/profiles never changes the code the user is looking at.
   */
  fun refreshQrCode() {
    val current = store.value
    if (current.isRegistering || current.qrState is QrState.Scanned || current.qrState is QrState.Loaded) {
      return
    }

    consecutiveFailures.set(0)

    if (startNewSocketJob?.isActive != true) {
      Log.i(TAG, "Socket loop is not running, restarting")
      restart()
    } else {
      Log.d(TAG, "Requesting a fresh QR code")
      store.update { if (it.qrState is QrState.Failed) it.copy(qrState = QrState.Loading) else it }
      reconnectNow.trySend(Unit)
    }
  }

  private fun reconnectDelay(failures: Int): Duration {
    val exponent = (failures - 1).coerceIn(0, 5)
    return (MIN_RECONNECT_DELAY * (1 shl exponent)).coerceAtMost(MAX_RECONNECT_DELAY)
  }

  /**
   * A socket died. Retry only while no QR code has been shown yet; once one is on screen it stays there.
   */
  private fun onSocketFailure(id: Int, t: Throwable) {
    val current = store.value

    if (current.isRegistering || current.qrState is QrState.Scanned) {
      Log.i(TAG, "Socket [$id] failed after the code was scanned, ignoring")
      return
    }

    if (current.currentSocketId != null && current.currentSocketId != id) {
      Log.i(TAG, "Old socket [$id] failed, ignoring")
      return
    }

    // MOLLY: Keep the displayed code even though its socket is gone and it can no longer be used to link.
    // Regenerating is the only way to stay linkable, but it also changes the code mid-scan, which is worse
    // for this workflow. The user retries explicitly instead.
    if (current.qrState is QrState.Loaded) {
      Log.w(TAG, "Current socket [$id] failed, keeping the displayed QR code (it will no longer link)", t)
      return
    }

    val failures = consecutiveFailures.incrementAndGet()
    Log.w(TAG, "Current socket [$id] has failed ($failures in a row), reconnecting", t)

    store.update {
      when {
        it.isRegistering || it.qrState is QrState.Scanned -> it
        it.currentSocketId != null && it.currentSocketId != id -> it
        failures >= FAILURES_BEFORE_ERROR -> it.copy(currentSocketId = null, qrState = QrState.Failed)
        else -> it.copy(currentSocketId = null, qrState = QrState.Loading)
      }
    }

    reconnectNow.trySend(Unit)
  }

  fun handleRegistrationFailure(registerAccountResult: RegisterAccountResult) {
    store.update {
      if (it.isRegistering) {
        Log.w(TAG, "Unable to register [${registerAccountResult::class.simpleName}]", registerAccountResult.getCause(), true)
        it.copy(
          isRegistering = false,
          provisioningMessage = null,
          showRegistrationError = true,
          registerAccountResult = registerAccountResult
        )
      } else {
        it
      }
    }
  }

  fun clearRegistrationError() {
    store.update {
      it.copy(
        showRegistrationError = false,
        registerAccountResult = null
      )
    }

    restart()
  }

  override fun onCleared() {
    shutdown()
  }

  private fun startNewSocket() {
    synchronized(socketHandles) {
      socketHandles += start()

      if (socketHandles.size > 2) {
        socketHandles.removeAt(0).close()
      }
    }
  }

  private fun shutdown() {
    startNewSocketJob?.cancel()
    synchronized(socketHandles) {
      socketHandles.forEach { it.close() }
      socketHandles.clear()
    }
  }

  private fun start(): Closeable {
    return ProvisioningSocket.start<RegistrationProvisionMessage>(
      mode = ProvisioningSocket.Mode.Rereg,
      identityKeyPair = IdentityKeyPair.generate(),
      configuration = AppDependencies.signalServiceNetworkAccess.getConfiguration(),
      handler = { id, t -> onSocketFailure(id, t) }
    ) { socket ->
      val url = socket.getProvisioningUrl()
      consecutiveFailures.set(0)
      store.update {
        Log.d(TAG, "Updating QR code with data from [${socket.id}]", true)

        it.copy(
          currentSocketId = socket.id,
          qrState = QrState.Loaded(
            qrData = QrCodeData.forData(
              data = url,
              supportIconOverlay = false
            )
          )
        )
      }

      val result = socket.getProvisioningMessageDecryptResult()

      Log.d(TAG, "Received provisioning message result", true)

      if (result is SecondaryProvisioningCipher.ProvisioningDecryptResult.Success) {
        Log.i(TAG, "Success! Saving restore method token: ***${result.message.restoreMethodToken.takeLast(4)}", true)
        SignalStore.registration.restoreMethodToken = result.message.restoreMethodToken
        SignalStore.registration.restoreBackupMediaSize = result.message.backupSizeBytes ?: 0
        SignalStore.registration.isOtherDeviceAndroid = result.message.platform == RegistrationProvisionMessage.Platform.ANDROID

        SignalStore.backup.lastBackupTime = result.message.backupTimestampMs ?: 0
        SignalStore.backup.isBackupTimestampRestored = true
        SignalStore.backup.restoringViaQr = true
        SignalStore.backup.backupTier = when (result.message.tier) {
          RegistrationProvisionMessage.Tier.FREE -> MessageBackupTier.FREE
          RegistrationProvisionMessage.Tier.PAID -> MessageBackupTier.PAID
          null -> null
        }

        store.update { it.copy(isRegistering = true, provisioningMessage = result.message, qrState = QrState.Scanned) }
        shutdown()
      } else {
        store.update {
          if (it.currentSocketId == socket.id) {
            it.copy(showProvisioningError = true, qrState = QrState.Scanned)
          } else {
            it
          }
        }
      }
    }
  }

  data class RestoreViaQrState(
    val isRegistering: Boolean = false,
    val qrState: QrState = QrState.Loading,
    val provisioningMessage: RegistrationProvisionMessage? = null,
    val showProvisioningError: Boolean = false,
    val showRegistrationError: Boolean = false,
    val registerAccountResult: RegisterAccountResult? = null,
    val currentSocketId: Int? = null
  )

  sealed interface QrState {
    data object Loading : QrState
    data class Loaded(val qrData: QrCodeData) : QrState
    data object Failed : QrState
    data object Scanned : QrState
  }
}
