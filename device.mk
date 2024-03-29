#
# Copyright (C) 2016 The Android Open-Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This file includes all definitions that apply to ALL bullhead devices, and
# are also specific to bullhead devices
#
# Everything in this directory will become public

# Boot animation
TARGET_SCREEN_HEIGHT := 1920
TARGET_SCREEN_WIDTH := 1080

# setup dalvik vm configs.
$(call inherit-product, frameworks/native/build/phone-xhdpi-2048-dalvik-heap.mk)

# Dexpreopt
WITH_DEXPREOPT := true
WITH_DEXPREOPT_PIC := true

# Enable support for chinook sensorhub
TARGET_USES_CHINOOK_SENSORHUB := false


PRODUCT_COPY_FILES += \
    device/lge/bullhead/init.bullhead.rc:root/init.bullhead.rc \
    device/lge/bullhead/init.bullhead.usb.rc:root/init.bullhead.usb.rc \
    device/lge/bullhead/fstab.bullhead:root/fstab.bullhead \
    device/lge/bullhead/ueventd.bullhead.rc:root/ueventd.bullhead.rc \
    device/lge/bullhead/init.recovery.bullhead.rc:recovery/root/init.recovery.bullhead.rc \
    device/lge/bullhead/init.bullhead.ramdump.rc:root/init.bullhead.ramdump.rc \
    device/lge/bullhead/init.bullhead.fp.rc:root/init.bullhead.fp.rc \
    device/lge/bullhead/init.qcom.devwait.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.qcom.devwait.sh \
    device/lge/bullhead/init.qcom.devstart.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.qcom.devstart.sh \
    device/lge/bullhead/fstab.bullhead:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.bullhead \
    device/lge/bullhead/fstab.bullhead:$(TARGET_COPY_OUT_RAMDISK)/fstab.bullhead

ifeq ($(TARGET_USES_CHINOOK_SENSORHUB),true)
PRODUCT_COPY_FILES += \
    device/lge/bullhead/init.bullhead.sensorhub.rc:root/init.bullhead.sensorhub.rc
else
PRODUCT_COPY_FILES += \
    device/lge/bullhead/init.bullhead.nanohub.rc:root/init.bullhead.sensorhub.rc
endif

PRODUCT_COPY_FILES += \
    frameworks/av/media/libstagefright/data/media_codecs_google_audio.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/media_codecs_google_audio.xml \
    frameworks/av/media/libstagefright/data/media_codecs_google_telephony.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/media_codecs_google_telephony.xml \
    frameworks/av/media/libstagefright/data/media_codecs_google_video_le.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/media_codecs_google_video_le.xml \
    device/lge/bullhead/media_codecs.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/media_codecs.xml \
    device/lge/bullhead/media_codecs_performance.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/media_codecs_performance.xml \
    device/lge/bullhead/media_profiles.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/media_profiles.xml

# APEX
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/configs/ld.config.txt:$(TARGET_COPY_OUT_SYSTEM)/etc/swcodec/ld.config.txt

# Audio
PRODUCT_COPY_FILES += \
    device/lge/bullhead/audio_effects.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_effects.xml \
    device/lge/bullhead/mixer_paths.xml:$(TARGET_COPY_OUT_VENDOR)/etc/mixer_paths.xml \
    device/lge/bullhead/audio_platform_info.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/audio_platform_info.xml \
    device/lge/bullhead/audio_policy_configuration.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/audio_policy_configuration.xml \
    device/lge/bullhead/audio_policy_volumes_drc.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/audio_policy_volumes_drc.xml \
    frameworks/av/services/audiopolicy/config/a2dp_audio_policy_configuration.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/a2dp_audio_policy_configuration.xml \
    frameworks/av/services/audiopolicy/config/bluetooth_audio_policy_configuration.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/bluetooth_audio_policy_configuration.xml \
    frameworks/av/services/audiopolicy/config/r_submix_audio_policy_configuration.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/r_submix_audio_policy_configuration.xml \
    frameworks/av/services/audiopolicy/config/usb_audio_policy_configuration.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/usb_audio_policy_configuration.xml \
    frameworks/av/services/audiopolicy/config/default_volume_tables.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/default_volume_tables.xml \

PRODUCT_PROPERTY_OVERRIDES += \
    persist.bt.enableAptXHD=true \
    persist.service.btui.use_aptx=1 \
    persist.vendor.bt.a2dp_offload_cap=sbc-aptx-aptxtws-aptxhd-aac-ldac \
    persist.vendor.btstack.a2dp_offload_cap=sbc-aptx-aptxtws-aptxhd-aac-ldac

#Sound Trigger
PRODUCT_COPY_FILES += \
    device/lge/bullhead/sound_trigger_mixer_paths.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/sound_trigger_mixer_paths.xml \
    device/lge/bullhead/sound_trigger_platform_info.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/sound_trigger_platform_info.xml

# Input device files
PRODUCT_COPY_FILES += \
    device/lge/bullhead/gpio-keys.kl:$(TARGET_COPY_OUT_SYSTEM)/usr/keylayout/gpio-keys.kl \
    device/lge/bullhead/qpnp_pon.kl:$(TARGET_COPY_OUT_SYSTEM)/usr/keylayout/qpnp_pon.kl \
    device/lge/bullhead/uinput-fpc.idc:$(TARGET_COPY_OUT_SYSTEM)/usr/idc/uinput-fpc.idc \
    device/lge/bullhead/uinput-fpc.kl:$(TARGET_COPY_OUT_SYSTEM)/usr/keylayout/uinput-fpc.kl

# Prebuilt input device calibration files
PRODUCT_COPY_FILES += \
    device/lge/bullhead/synaptics_rmi4_i2c.idc:system/usr/idc/synaptics_rmi4_i2c.idc

# These are the hardware-specific features
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/handheld_core_hardware.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/handheld_core_hardware.xml \
    frameworks/native/data/etc/android.hardware.bluetooth_le.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.bluetooth_le.xml \
    frameworks/native/data/etc/android.hardware.camera.flash-autofocus.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.camera.flash-autofocus.xml \
    frameworks/native/data/etc/android.hardware.camera.front.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.camera.front.xml \
    frameworks/native/data/etc/android.hardware.camera.full.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.camera.full.xml \
    frameworks/native/data/etc/android.hardware.camera.raw.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.camera.raw.xml \
    frameworks/native/data/etc/android.hardware.fingerprint.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.fingerprint.xml \
    frameworks/native/data/etc/android.hardware.location.gps.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.location.gps.xml \
    frameworks/native/data/etc/android.hardware.wifi.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.wifi.xml \
    frameworks/native/data/etc/android.hardware.wifi.direct.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.wifi.direct.xml \
    frameworks/native/data/etc/android.hardware.wifi.passpoint.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.wifi.passpoint.xml \
    frameworks/native/data/etc/android.hardware.sensor.proximity.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.sensor.proximity.xml \
    frameworks/native/data/etc/android.hardware.sensor.light.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.sensor.light.xml \
    frameworks/native/data/etc/android.hardware.sensor.gyroscope.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.sensor.gyroscope.xml \
    frameworks/native/data/etc/android.hardware.sensor.barometer.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.sensor.barometer.xml \
    frameworks/native/data/etc/android.hardware.sensor.stepcounter.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.sensor.stepcounter.xml \
    frameworks/native/data/etc/android.hardware.sensor.stepdetector.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.sensor.stepdetector.xml \
    frameworks/native/data/etc/android.hardware.sensor.hifi_sensors.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.sensor.hifi_sensors.xml \
    frameworks/native/data/etc/android.hardware.touchscreen.multitouch.jazzhand.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.touchscreen.multitouch.jazzhand.xml \
    frameworks/native/data/etc/android.software.sip.voip.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.software.sip.voip.xml \
    frameworks/native/data/etc/android.hardware.usb.accessory.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.usb.accessory.xml \
    frameworks/native/data/etc/android.hardware.usb.host.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.usb.host.xml \
    frameworks/native/data/etc/android.hardware.audio.low_latency.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.audio.low_latency.xml \
    frameworks/native/data/etc/android.hardware.audio.pro.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.audio.pro.xml \
    frameworks/native/data/etc/android.hardware.telephony.cdma.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.telephony.cdma.xml \
    frameworks/native/data/etc/android.hardware.telephony.ims.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.telephony.ims.xml \
    frameworks/native/data/etc/android.hardware.telephony.gsm.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.telephony.gsm.xml \
    frameworks/native/data/etc/android.hardware.nfc.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.nfc.xml \
    frameworks/native/data/etc/android.hardware.nfc.hce.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.nfc.hce.xml \
    frameworks/native/data/etc/android.hardware.nfc.hcef.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.nfc.hcef.xml \
    frameworks/native/data/etc/android.hardware.ethernet.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.ethernet.xml \
    frameworks/native/data/etc/android.software.midi.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.software.midi.xml \
    frameworks/native/data/etc/android.software.verified_boot.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.software.verified_boot.xml \
    frameworks/native/data/etc/com.nxp.mifare.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/com.nxp.mifare.xml \
    frameworks/native/data/etc/android.hardware.opengles.aep.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.opengles.aep.xml \
    frameworks/native/data/etc/android.hardware.vulkan.level-0.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.vulkan.level.xml \
    frameworks/native/data/etc/android.hardware.vulkan.version-1_0_3.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/permissions/android.hardware.vulkan.version.xml

# For GPS
PRODUCT_COPY_FILES += \
    device/lge/bullhead/sec_config:$(TARGET_COPY_OUT_SYSTEM)/etc/sec_config

# NFC config files
PRODUCT_COPY_FILES += \
    device/lge/bullhead/nfc/libnfc-nci.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-nci.conf \
    device/lge/bullhead/nfc/libnfc-nxp.conf:$(TARGET_COPY_OUT_VENDOR)/etc/libnfc-nxp.conf

# For WiFi
PRODUCT_COPY_FILES += \
    device/lge/bullhead/wifi/wpa_supplicant_overlay.conf:$(TARGET_COPY_OUT_VENDOR)/etc/wifi/wpa_supplicant_overlay.conf \
    device/lge/bullhead/wifi/p2p_supplicant_overlay.conf:$(TARGET_COPY_OUT_VENDOR)/etc/wifi/p2p_supplicant_overlay.conf \
    device/lge/bullhead/wifi/WCNSS_cfg.dat:$(TARGET_COPY_OUT_SYSTEM)/etc/firmware/wlan/qca_cld/WCNSS_cfg.dat \
    device/lge/bullhead/wifi/WCNSS_qcom_cfg.ini:$(TARGET_COPY_OUT_SYSTEM)/etc/firmware/wlan/qca_cld/WCNSS_qcom_cfg.ini

# MSM IRQ Balancer configuration file
PRODUCT_COPY_FILES += \
    device/lge/bullhead/msm_irqbalance.conf:$(TARGET_COPY_OUT_VENDOR)/etc/msm_irqbalance.conf

# Power configuration file
PRODUCT_COPY_FILES += \
    device/lge/bullhead/init.bullhead.power.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.bullhead.power.sh

# MBN
PRODUCT_COPY_FILES += \
    device/lge/bullhead/init.bullhead.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.bullhead.sh

# Qseecomd configuration file
PRODUCT_COPY_FILES += \
    device/lge/bullhead/init.bullhead.qseecomd.sh:$(TARGET_COPY_OUT_VENDOR)/bin/init.bullhead.qseecomd.sh

PRODUCT_TAGS += dalvik.gc.type-precise

PRODUCT_AAPT_CONFIG := normal
PRODUCT_AAPT_PREF_CONFIG := xxhdpi
# A list of dpis to select prebuilt apk, in precedence order.
PRODUCT_AAPT_PREBUILT_DPI := xxhdpi xhdpi hdpi

PRODUCT_CHARACTERISTICS := nosdcard

# for off charging mode
PRODUCT_PACKAGES += \
    charger_res_images

PRODUCT_PACKAGES += \
    gralloc.msm8992 \
    android.hardware.graphics.allocator@2.0-impl \
    android.hardware.graphics.allocator@2.0-service \
    android.hardware.graphics.mapper@2.0-impl \
    android.hardware.graphics.mapper@2.0-service \
    hwcomposer.msm8992 \
    libgenlock \
    memtrack.msm8992 \
    android.hardware.memtrack@1.0-impl \
    android.hardware.memtrack@1.0-service

# libcutils
PRODUCT_PACKAGES += \
    libcutils_shim

# libprotobuf
PRODUCT_PACKAGES += \
    libprotobuf_shim

# Light HAL
PRODUCT_PACKAGES += \
    lights.vts \
    android.hardware.light@2.0-service.bullhead

# RenderScript HAL
PRODUCT_PACKAGES += \
    android.hardware.renderscript@1.0-impl

PRODUCT_PACKAGES += \
    android.hardware.drm@1.0-impl \
    android.hardware.drm@1.0-service \
    android.hardware.drm@1.2-service.clearkey

PRODUCT_PACKAGES += \
    libc2dcolorconvert \
    libstagefrighthw \
    libOmxCore \
    libmm-omxcore \
    libOmxVdec \
    libOmxVdecHevc \
    libOmxVenc

# Audio HAL and utilities
USE_XML_AUDIO_POLICY_CONF := 1
PRODUCT_PACKAGES += \
    audio.primary.msm8992 \
    audio.a2dp.default \
    audio.usb.default \
    audio.r_submix.default \
    libaudio-resampler \
    dsm_ctrl

# Audio effects
PRODUCT_PACKAGES += \
    libqcomvoiceprocessing \
    libqcomvoiceprocessingdescriptors \
    libqcomvisualizer \
    libqcompostprocbundle \
    libvolumelistener

# Dumpstate HAL
PRODUCT_PACKAGES += \
    android.hardware.dumpstate@1.0-service.bullhead

PRODUCT_PACKAGES += \
    libaudioclient_shim \
    librmnetctl \
    rmnetcli

PRODUCT_PACKAGES += \
    android.hardware.audio@2.0-service \
    android.hardware.audio@2.0-impl \
    android.hardware.soundtrigger@2.0-impl \
    android.hardware.audio.effect@2.0-impl

PRODUCT_PACKAGES += \
    android.hardware.graphics.composer@2.1-impl \
    android.hardware.graphics.composer@2.1-service

# GPS configuration
PRODUCT_COPY_FILES += \
    device/lge/bullhead/gps.conf:$(TARGET_COPY_OUT_SYSTEM)/etc/gps.conf

# GPS
PRODUCT_PACKAGES += \
    libgps.utils \
    libgnss \
    liblocation_api \
    gps.msm8992

# Health HAL
PRODUCT_PACKAGES += \
    android.hardware.health@2.0-service.bullhead

# NFC packages
PRODUCT_PACKAGES += \
    libnfc-nci \
    NfcNci \
    Tag \
    android.hardware.nfc@1.1-service

# Keymaster HAL
PRODUCT_PACKAGES += \
    android.hardware.keymaster@3.0-impl \
    android.hardware.keymaster@3.0-service

# Vibrator HAL
PRODUCT_PACKAGES += \
    android.hardware.vibrator@1.0-impl

# Fingerprint HIDL implementation
PRODUCT_PACKAGES += \
    fingerprint.bullhead \
    android.hardware.biometrics.fingerprint@2.1-service

# Wi-Fi
PRODUCT_PACKAGES += \
    android.hardware.wifi@1.0-service \
    libwpa_client \
    hostapd \
    wificond \
    wifilogd \
    wpa_supplicant \
    wpa_supplicant.conf

# Camera
PRODUCT_PACKAGES += \
    camera.msm8992 \
    libcamera \
    libmmcamera_interface \
    libmmcamera_interface2 \
    libmmjpeg_interface \
    libqomx_core \
    mm-qcamera-app \
    android.hardware.camera.provider@2.4-impl \
    camera.device@1.0-impl \
    camera.device@3.2-impl

PRODUCT_PACKAGES += \
    vendor.qti.hardware.camera.device@1.0 \
    vendor.qti.hardware.camera.device@1.0_vendor

# IMS
PRODUCT_PACKAGES += \
    com.android.ims.rcsmanager

# Enable camera EIS
# eis.enable: enables electronic image stabilization
# is_type: sets image stabilization type
PRODUCT_PROPERTY_OVERRIDES += \
    persist.camera.eis.enable=1 \
    persist.camera.is_type=4

# Sensor & activity_recognition HAL
TARGET_USES_NANOHUB_SENSORHAL := true
NANOHUB_SENSORHAL_LID_STATE_ENABLED := true
NANOHUB_SENSORHAL_SENSORLIST := $(LOCAL_PATH)/sensorhal/sensorlist.cpp
NANOHUB_SENSORHAL_DIRECT_REPORT_ENABLED := true

PRODUCT_PACKAGES += \
    sensors.bullhead \
    activity_recognition.bullhead \
    android.hardware.sensors@1.0-impl \
    android.hardware.contexthub@1.0-impl.nanohub \
    android.hardware.contexthub@1.0-service

# new gatekeeper HAL
PRODUCT_PACKAGES += \
    android.hardware.gatekeeper@1.0-impl \
    android.hardware.gatekeeper@1.0-service   

ifeq ($(TARGET_USES_CHINOOK_SENSORHUB),true)
PRODUCT_PACKAGES += \
    sensortool.bullhead
else
PRODUCT_PACKAGES += \
    nanoapp_cmd
endif

# sensor utilities (only for userdebug and eng builds)
ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
PRODUCT_PACKAGES += \
    nanotool \
    sensortest
endif

# Library used for VTS profiling (only for userdebug and eng builds)
ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
PRODUCT_PACKAGES += \
    libvts_profiling \
    libvts_multidevice_proto
endif

PRODUCT_PACKAGES += \
    gatekeeper.msm8992

# general support
PRODUCT_PACKAGES += \
    libtinyxml

# TimeKeep
PRODUCT_PACKAGES += \
    timekeep \
    TimeKeep
    
# GoogleCamera
#$(call inherit-product, packages/apps/GoogleCamera/config.mk)

# For android_filesystem_config.h
PRODUCT_PACKAGES += \
   fs_config_files

# For wlan_mac.bin symlink
PRODUCT_PACKAGES += \
    bullhead_wlan_mac

DEVICE_PACKAGE_OVERLAYS := \
    device/lge/bullhead/overlay

# Enable AAC 5.1 output
PRODUCT_PROPERTY_OVERRIDES += \
    media.aac_51_output_enabled=true

# Audio
PRODUCT_PROPERTY_OVERRIDES += \
    ro.qc.sdk.audio.fluencetype=fluencepro \
    persist.audio.fluence.voicecall=true \
    persist.audio.fluence.voicecomm=true \
    persist.audio.fluence.voicerec=false \
    persist.audio.fluence.speaker=true \
    persist.speaker.prot.enable=true \
    ro.config.vc_call_vol_steps=7

# Default OMX service to non-Treble
PRODUCT_PROPERTY_OVERRIDES += \
    persist.media.treble_omx=false

# Media
PRODUCT_PROPERTY_OVERRIDES += \
    debug.stagefright.omx_default_rank.sw-audio=1
    debug.stagefright.omx_default_rank=0

# Write Manufacturer & Model information in created media files.
PRODUCT_PROPERTY_OVERRIDES += \
    media.recorder.show_manufacturer_and_model=true

# Reduce client buffer size for fast audio output tracks
PRODUCT_PROPERTY_OVERRIDES += \
    af.fast_track_multiplier=1

# Low latency audio buffer size in frames
PRODUCT_PROPERTY_OVERRIDES += \
    audio_hal.period_size=192

PRODUCT_PROPERTY_OVERRIDES += \
    wifi.interface=wlan0 \
    wifi.supplicant_scan_interval=15

PRODUCT_PROPERTY_OVERRIDES += \
    ro.opengles.version=196610

PRODUCT_PROPERTY_OVERRIDES += \
    ro.sf.lcd_density=420

PRODUCT_PROPERTY_OVERRIDES += \
    persist.hwc.mdpcomp.enable=true

# Enable low power video mode for 4K encode
PRODUCT_PROPERTY_OVERRIDES += \
    vidc.debug.perf.mode=2 \
    vidc.enc.dcvs.extra-buff-count=2

PRODUCT_PROPERTY_OVERRIDES += \
    ro.hwui.texture_cache_size=56 \
    ro.hwui.layer_cache_size=32 \
    ro.hwui.r_buffer_cache_size=8 \
    ro.hwui.path_cache_size=16 \
    ro.hwui.gradient_cache_size=1 \
    ro.hwui.drop_shadow_cache_size=6 \
    ro.hwui.texture_cache_flushrate=0.4 \
    ro.hwui.text_small_cache_width=1024 \
    ro.hwui.text_small_cache_height=1024 \
    ro.hwui.text_large_cache_width=2048 \
    ro.hwui.text_large_cache_height=1024

PRODUCT_PROPERTY_OVERRIDES += \
    ro.frp.pst=/dev/block/platform/soc.0/f9824900.sdhci/by-name/persistent

PRODUCT_PROPERTY_OVERRIDES += \
    drm.service.enabled=true

# for perfd
PRODUCT_PROPERTY_OVERRIDES += \
    ro.min_freq_0=384000 \
    ro.min_freq_4=384000

PRODUCT_PROPERTY_OVERRIDES += \
    ro.vendor.extension_library=libqti-perfd-client.so

PRODUCT_PROPERTY_OVERRIDES += \
    rild.libpath=/vendor/lib64/libril-qc-qmi-1.so

PRODUCT_PROPERTY_OVERRIDES += \
    ro.telephony.default_cdma_sub=0 \
    persist.qcril.disable_retry=true

PRODUCT_PACKAGES += \
    telephony-ext \
    ims-ext-common \
    ims_ext_common.xml \
    qti-telephony-hidl-wrapper \
    qti_telephony_hidl_wrapper.xml \
    qti-telephony-utils \
    qti_telephony_utils.xml \

PRODUCT_BOOT_JARS += \
    telephony-ext

# LTE, CDMA, GSM/WCDMA
PRODUCT_PROPERTY_OVERRIDES += \
    ro.telephony.default_network=22 \
    telephony.lteOnCdmaDevice=1 \
    persist.radio.mode_pref_nv10=1

# Emergency call overrides for Korea
PRODUCT_PROPERTY_OVERRIDES += \
    ril.nosim.ecc_list_count=1 \
    ril.nosim.ecc_list_1=111,113,117,122,125

# low audio flinger standby delay to reduce power consumption
PRODUCT_PROPERTY_OVERRIDES += \
    ro.audio.flinger_standbytime_ms=300

PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.apm_sim_not_pwdn=1

# Setup custom emergency number list based on the MCC. This is needed by RIL
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.custom_ecc=1

# Request modem to send PLMN name always irrespective
# of display condition in EFSPN.
# RIL uses this property.
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.always_send_plmn=true

# Ril sends only one RIL_UNSOL_CALL_RING, so set call_ring.multiple to false
PRODUCT_PROPERTY_OVERRIDES += \
    ro.telephony.call_ring.multiple=0

PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.use_cc_names=true

# Update 1x signal strength after 10s
PRODUCT_DEFAULT_PROPERTY_OVERRIDES += \
    persist.radio.snapshot_enabled=1 \
    persist.radio.snapshot_timer=10

# If data_no_toggle is 0 there are no reports if the screen is off.
# If data_no_toggle is 1 then dormancy indications will come with screen off.
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.data_no_toggle=1

# Adjust STK popup operation
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.process_sups_ind=1

# VZW voice roaming issue
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.eri64_as_home=1

PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.data_con_rprt=true

# Set bluetooth soc to rome
PRODUCT_PROPERTY_OVERRIDES += \
    qcom.bluetooth.soc=rome

# Set Bluetooth transport initialization timeout
PRODUCT_PROPERTY_OVERRIDES += \
    bluetooth.enable_timeout_ms=12000

PRODUCT_DEFAULT_PROPERTY_OVERRIDES += \
    ro.bt.bdaddr_path=/persist/bdaddr.txt

# Bluetooth HAL
PRODUCT_PACKAGES += \
    libbt-vendor \
    android.hardware.bluetooth@1.0-impl

# limit dex2oat threads to improve thermals
PRODUCT_PROPERTY_OVERRIDES += \
    dalvik.vm.boot-dex2oat-threads=4 \
    dalvik.vm.dex2oat-threads=4 \
    dalvik.vm.image-dex2oat-threads=4

# Disable Camera TNR
PRODUCT_PROPERTY_OVERRIDES += \
    persist.camera.tnr.preview=0 \
    persist.camera.tnr.video=0
    
PRODUCT_PROPERTY_OVERRIDES += \
    persist.camera.HAL3.enabled=1

# Incoming number (b/23529711)
PRODUCT_PROPERTY_OVERRIDES += \
    persist.radio.redir_party_num=0

# NFC/camera interaction workaround - DO NOT COPY TO NEW DEVICES
PRODUCT_PROPERTY_OVERRIDES += \
    ro.camera.notify_nfc=1

# Power HAL
PRODUCT_PACKAGES += \
    power.bullhead \
    android.hardware.power@1.0-impl \

# Thermal HAL
#PRODUCT_PACKAGES += \
#    thermal.bullhead \
#    android.hardware.thermal@1.0-impl \

#GNSS HAL
PRODUCT_PACKAGES += \
    android.hardware.gnss@1.0-impl \
    android.hardware.gnss@1.0-service

#USB HAL
PRODUCT_PACKAGES += \
    android.hardware.usb@1.0-service

# Modem debugger/misc
ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
ifeq (,$(filter aosp_bullhead, $(TARGET_PRODUCT)))
PRODUCT_PACKAGES += \
    NexusLogger
endif # aosp_bullhead

PRODUCT_COPY_FILES += \
    device/lge/bullhead/init.bullhead.diag.rc.userdebug:root/init.bullhead.diag.rc \
    device/lge/bullhead/init.bullhead.misc.rc.userdebug:root/init.bullhead.misc.rc
else
PRODUCT_COPY_FILES += \
    device/lge/bullhead/init.bullhead.diag.rc.user:root/init.bullhead.diag.rc \
    device/lge/bullhead/init.bullhead.misc.rc.user:root/init.bullhead.misc.rc
endif

# Set if a device image has the VTS coverage instrumentation.
ifeq ($(NATIVE_COVERAGE),true)
PRODUCT_PROPERTY_OVERRIDES += \
    ro.vts.coverage=1
endif

# only include verity on user builds for LineageOS
ifeq ($(TARGET_BUILD_VARIANT),user)
   PRODUCT_COPY_FILES += device/lge/bullhead/fstab-verity.bullhead:root/fstab.bullhead
endif

# OEM Unlock reporting
PRODUCT_DEFAULT_PROPERTY_OVERRIDES += \
    ro.oem_unlock_supported=1
	
# Disable rescue party
PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.disable_rescue=true

# Graphics
PRODUCT_DEFAULT_PROPERTY_OVERRIDES += \
    debug.sf.disable_backpressure=1 \
    debug.sf.enable_gl_backpressure=1 \
    debug.sf.latch_unsignaled=1 \
    ro.surface_flinger.force_hwc_copy_for_virtual_displays=true \
    ro.surface_flinger.max_frame_buffer_acquired_buffers=3 \
    ro.surface_flinger.max_virtual_display_dimension=2048 \
    ro.surface_flinger.vsync_event_phase_offset_ns=2000000 \
    ro.surface_flinger.vsync_sf_event_phase_offset_ns=6000000

# ro.product.first_api_level indicates the first api level the device has commercially launched on.
PRODUCT_PROPERTY_OVERRIDES += \
    ro.product.first_api_level=23

# facelock properties
PRODUCT_PROPERTY_OVERRIDES += \
    ro.facelock.black_timeout=700 \
    ro.facelock.det_timeout=2500 \
    ro.facelock.rec_timeout=3500 \
    ro.facelock.est_max_time=600

# ADB
ro.debuggable=1
persist.sys.usb.config=adb
ro.secure=0
ro.adb.secure=0

# Props for ims features
PRODUCT_PROPERTY_OVERRIDES += \
    persist.dbg.ims_volte_enable=1 \
    persist.dbg.volte_avail_ovr=1 \
    persist.dbg.vt_avail_ovr=1 \
    persist.dbg.wfc_avail_ovr=1 \
    persist.radio.rat_on=combine \
    persist.radio.data_ltd_sys_ind=1 \
    persist.radio.data_con_rprt=1 \
    persist.radio.calls.on.ims=1
    
# Privapp Whitelist
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/privapp-permissions-bullhead.xml:system/etc/permissions/privapp-permissions-bullhead.xml

$(call inherit-product-if-exists, hardware/qcom/msm8994/msm8992.mk)
$(call inherit-product-if-exists, vendor/qcom/gpu/msm8994/msm8994-gpu-vendor.mk)
