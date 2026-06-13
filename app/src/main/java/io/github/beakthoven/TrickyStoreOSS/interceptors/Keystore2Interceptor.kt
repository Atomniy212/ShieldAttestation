/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS.interceptors

import android.annotation.SuppressLint
import android.hardware.security.keymint.SecurityLevel
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import io.github.beakthoven.TrickyStoreOSS.CertificateHack
import io.github.beakthoven.TrickyStoreOSS.CertificateUtils
import io.github.beakthoven.TrickyStoreOSS.KeyBoxUtils
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.createTypedObjectReply
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.getTransactCode
import io.github.beakthoven.TrickyStoreOSS.interceptors.InterceptorUtils.hasException
import io.github.beakthoven.TrickyStoreOSS.logging.Logger
import io.github.beakthoven.TrickyStoreOSS.putCertificateChain

@SuppressLint("BlockedPrivateApi")
object Keystore2Interceptor : BaseKeystoreInterceptor() {
    private val getKeyEntryTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "getKeyEntry")
    private val deleteKeyTransaction =
        getTransactCode(IKeystoreService.Stub::class.java, "deleteKey")
    
    override val serviceName = "android.system.keystore2.IKeystoreService/default"
    override val processName = "keystore2"
    override val injectionCommand = "exec ./inject `pidof keystore2` libShieldAttestation.so entry"

    private var teeInterceptor: SecurityLevelInterceptor? = null
    private var strongBoxInterceptor: SecurityLevelInterceptor? = null
    
    override fun onInterceptorSetup(service: IBinder, backdoor: IBinder) {
        setupSecurityLevelInterceptors(service, backdoor)
    }
    
    private fun setupSecurityLevelInterceptors(service: IBinder, backdoor: IBinder) {
        val ks = IKeystoreService.Stub.asInterface(service)
        
        val tee = kotlin.runCatching { ks.getSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT) }
            .getOrNull()
        if (tee != null) {
            Logger.i("Registering for TEE SecurityLevel: $tee")
            val interceptor = SecurityLevelInterceptor(tee, SecurityLevel.TRUSTED_ENVIRONMENT)
            registerBinderInterceptor(backdoor, tee.asBinder(), interceptor)
            teeInterceptor = interceptor
        } else {
            Logger.i("No TEE SecurityLevel found")
        }
        
        val strongBox = kotlin.runCatching { ks.getSecurityLevel(SecurityLevel.STRONGBOX) }
            .getOrNull()
        if (strongBox != null) {
            Logger.i("Registering for StrongBox SecurityLevel: $strongBox")
            val interceptor = SecurityLevelInterceptor(strongBox, SecurityLevel.STRONGBOX)
            registerBinderInterceptor(backdoor, strongBox.asBinder(), interceptor)
            strongBoxInterceptor = interceptor
        } else {
            Logger.i("No StrongBox SecurityLevel found")
        }
    }

    /**
     * Isolated processes (uid % 100000 >= 90000) must not hit the alias cache lookup in
     * onPreTransact — the cache key is indexed by uid+alias and isolated UIDs are ephemeral,
     * so a cache miss would return a null KeyEntryResponse, crashing the caller.
     *
     * onPostTransact is also guarded by the PkgConfig check (see below). GMS's attestation
     * flow uses entirely fake keys created by onPreTransact OverrideReply; those keys do not
     * exist in real Keystore so any isolated getKeyEntry call returns an exception reply which
     * is caught by reply.hasException() before the PkgConfig check is reached.
     */
    private fun isIsolatedUid(uid: Int): Boolean = (uid % 100000) >= 90000

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        if (isIsolatedUid(callingUid)) return Skip
        if (code == getKeyEntryTransaction) {
            if (KeyBoxUtils.hasKeyboxes()) {
                Logger.d("intercept pre  $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()}")
                try {
                    data.enforceInterface(IKeystoreService.DESCRIPTOR)
                    val descriptor = data.readTypedObject(KeyDescriptor.CREATOR) ?: return Skip
                    if (PkgConfig.needGenerate(callingUid)) {
                        val response = SecurityLevelInterceptor.getKeyResponse(callingUid, descriptor.alias)
                        if (response != null) {
                            Logger.i("Found generated response for uid=$callingUid alias=${descriptor.alias}")
                            return createTypedObjectReply(response)
                        } else {
                            Logger.e("No generated response found for uid=$callingUid alias=${descriptor.alias}")
                            val nullParcel = Parcel.obtain()
                            nullParcel.writeTypedObject(null as KeyEntryResponse?, 0)
                            return OverrideReply(0, nullParcel)
                        }
                    } else if (PkgConfig.needHack(callingUid)) {
                        if (SecurityLevelInterceptor.shouldSkipLeafHack(callingUid, descriptor.alias)) {
                            Logger.i("skip leaf hack for uid=$callingUid alias=${descriptor.alias}")
                            val response = SecurityLevelInterceptor.getKeyResponse(callingUid, descriptor.alias)
                            if (response != null) {
                                Logger.i("Found generated response for uid=$callingUid alias=${descriptor.alias}")
                                return createTypedObjectReply(response)
                            } else {
                                Logger.e("No generated response found for uid=$callingUid alias=${descriptor.alias}")
                                val nullParcel = Parcel.obtain()
                                nullParcel.writeTypedObject(null as KeyEntryResponse?, 0)
                                return OverrideReply(0, nullParcel)
                            }
                        } else {
                            Logger.i("proceeding with leaf hack for uid=$callingUid alias=${descriptor.alias}")
                            return Continue
                        }
                    }
                    return Skip
                } catch (e: Exception) {
                    Logger.e("Exception in onPreTransact uid=$callingUid pid=$callingPid!", e)
                    return Skip
                }
            }
        }
        return Skip
    }

    override fun onPostTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel,
        reply: Parcel?,
        resultCode: Int
    ): Result {
        if (target != keystore || reply == null) return Skip
        if (reply.hasException()) return Skip
        val p = Parcel.obtain()
        Logger.d("intercept post $target uid=$callingUid pid=$callingPid dataSz=${data.dataSize()} replySz=${reply.dataSize()}")

        if (code == deleteKeyTransaction && resultCode == 0) {
            data.enforceInterface("android.system.keystore2.IKeystoreService")

            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            if (keyDescriptor == null || keyDescriptor.domain == 0) return Skip

            SecurityLevelInterceptor.keys.remove(SecurityLevelInterceptor.Key(callingUid, keyDescriptor.alias))

            return Skip
        } else if (code == getKeyEntryTransaction) {
            // Spoof certs for:
            //   • target apps (needHack/needGenerate) — keybox cert needed for STRONG integrity
            //   • isolated processes (uid % 100000 >= 90000) — GMS attestation worker runs in an
            //     isolated process whose UID is NOT in PkgConfig; it still needs the keybox cert
            //     from getKeyEntry so Play Integrity returns STRONG, not BASIC.
            //
            // Non-target, non-isolated apps (e.g. Duck Detector) get the real TEE cert here.
            // SecurityLevelInterceptor.onPostTransact also skips them for generateKey, so both
            // paths return the real cert → consistent → Patch-mode / Binder-chain detections pass.
            // hackCertificateChain is non-deterministic (fresh timestamp each call); hacking both
            // paths for the same alias would produce two different certs — still a mismatch.
            if (!PkgConfig.needHack(callingUid) && !PkgConfig.needGenerate(callingUid) && !isIsolatedUid(callingUid)) return Skip
            try {
                data.enforceInterface("android.system.keystore2.IKeystoreService")
                val response = reply.readTypedObject(KeyEntryResponse.CREATOR)
                if (response != null) {
                    val chain = CertificateUtils.run { response.getCertificateChain() }
                if (chain != null) {
                        val newChain = CertificateHack.hackCertificateChain(chain)
                        response.putCertificateChain(newChain).getOrThrow()
                        Logger.i("Hacked certificate for uid=$callingUid")
                        return createTypedObjectReply(response)
                    } else {
                        p.recycle()
                    }
                } else {
                    p.recycle()
                }
            } catch (t: Throwable) {
                Logger.e("failed to hack certificate chain of uid=$callingUid pid=$callingPid!", t)
                p.recycle()
            }
        }
        return Skip
    }
}