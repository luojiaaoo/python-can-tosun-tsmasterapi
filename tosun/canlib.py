import atexit
import logging
import time
from collections import defaultdict
from queue import Queue, Empty
from typing import List
import can
import ctypes
from can import BusABC
from . import TSMasterApi
from threading import Lock

log = logging.getLogger("can.TSMasterApi")
log.setLevel(logging.WARN)
handler = logging.StreamHandler()
log.addHandler(handler)

DLC2BYTE_LEN = {
    0: 0,
    1: 1,
    2: 2,
    3: 3,
    4: 4,
    5: 5,
    6: 6,
    7: 7,
    8: 8,
    9: 12,
    10: 16,
    11: 20,
    12: 24,
    13: 32,
    14: 48,
    15: 64,
}
BYTE_LEN2DLC = {j: i for i, j in DLC2BYTE_LEN.items()}
APP_NAME = "ForTSMasterApi"

open_lib = False
open_lib_lock = Lock()


def _build_canfd_payload(msg: can.Message):
    payload_length = msg.dlc
    if payload_length < 0:
        raise ValueError("CAN FD消息长度不能为负数")
    if payload_length > 64:
        raise ValueError("CAN FD消息长度不能超过64字节")

    payload = bytearray(msg.data[:payload_length])
    fd_dlc = can.util.len2dlc(payload_length)
    frame_length = can.util.dlc2len(fd_dlc)
    if len(payload) < frame_length:
        payload.extend(b"\x00" * (frame_length - len(payload)))
    return payload, fd_dlc


def _format_ts_error(code: int) -> str:
    try:
        description = TSMasterApi.tsapp_get_error_description(code)
    except Exception:
        description = "未知错误"

    if isinstance(description, bytes):
        description = description.decode("utf8", errors="ignore")

    return f"错误码={code}, 描述={description}"


def _ensure_tsmaster_initialized():
    global open_lib

    if open_lib:
        return

    with open_lib_lock:
        if open_lib:
            return

        ret = TSMasterApi.initialize_lib_tsmaster(APP_NAME.encode("utf8"))
        if ret != 0:
            raise ValueError(f"初始化TSMaster失败，{_format_ts_error(ret)}")

        open_lib = True


def _activate_current_application():
    _ensure_tsmaster_initialized()
    ret = TSMasterApi.tsapp_set_current_application(APP_NAME.encode("utf8"))
    if ret != 0:
        raise ValueError(f"设置TSMaster应用失败，{_format_ts_error(ret)}")


def clean_tosun_lib():
    global open_lib
    if open_lib:
        log.debug('中止TSMaster DLL调用')
        TSMasterApi.finalize_lib_tsmaster()
        open_lib = False


atexit.register(clean_tosun_lib)

listcanfdmsg = (TSMasterApi.TLIBCANFD * 1000)()
listcanmsg = (TSMasterApi.TLIBCAN * 1000)()


class TSMasterApiBus(BusABC):
    _PRODUCTS = {
        "TC1001": {"fd": False, "channel_count": 1, "sub_type": 3},
        "TC1011": {"fd": True, "channel_count": 1, "sub_type": 5},
        "TC1014": {"fd": True, "channel_count": 4, "sub_type": 8},
        "TC1026": {"fd": True, "channel_count": 1, "sub_type": 10},
        "TC1016": {"fd": True, "channel_count": 4, "sub_type": 11},
        "TC1012": {"fd": True, "channel_count": 1, "sub_type": 12},
        "TC1013": {"fd": True, "channel_count": 2, "sub_type": 13},
        "Tlog1002": {"fd": True, "channel_count": 2, "sub_type": 14},
        "TC1034": {"fd": True, "channel_count": 2, "sub_type": 15},
        "TC1018": {"fd": True, "channel_count": 12, "sub_type": 16},
        "MP1013": {"fd": True, "channel_count": 2, "sub_type": 19},  # pcie
        "TC1113": {"fd": True, "channel_count": 2, "sub_type": 20},  # wifi
        "TC1114": {"fd": True, "channel_count": 4, "sub_type": 21},  # wifi
        "TP1013": {"fd": True, "channel_count": 2, "sub_type": 22},  # pcie
        "TC1017": {"fd": True, "channel_count": 8, "sub_type": 23},
        "TP1018": {"fd": True, "channel_count": 12, "sub_type": 24},  # pcie
        "Tlog1004": {"fd": True, "channel_count": 4, "sub_type": 26},
        "TP1034": {"fd": True, "channel_count": 2, "sub_type": 29},  # pcie
        "TP1026": {"fd": True, "channel_count": 1, "sub_type": 31},  # pcie
        "TC1038Pro": {"fd": True, "channel_count": 12, "sub_type": 45},
        "TC1055Pro": {"fd": True, "channel_count": 4, "sub_type": 49},  # TS_USB_IF_DEVICE
    }
    PRODUCTS = defaultdict(lambda: {"fd": True, "channel_count": 1, "sub_type": 0}, _PRODUCTS)

    def __init__(
            self,
            channel: int,
            device_name: str,  # 设备名
            device_type: int,  # 硬件类型
            hw_sn: str,  # 序列号
            hw_index: int,  # 设备索引，用于区分同型号设备，从0开始
            fd: bool = True,
            bitrate: int = 500000,
            data_bitrate: int = 2000000,
            receive_own_messages: bool = False,
            can_filters: List[int] = None,
            m120: bool = False,  # 是否开启120欧姆终端电阻
            fifo_mode: bool = True, # 默认fifo模式
            **kwargs,
    ):
        self.channel = channel
        self.device_name = device_name
        self.device_type = device_type
        self.hw_index = hw_index
        self.fd = fd
        self.m120 = m120
        self.queue_recv = Queue()
        self.send_async_count = 0
        self.fifo_mode = fifo_mode
        self.id_filters = None
        self.receive_own_messages = receive_own_messages
        _activate_current_application()
        can_ret = TSMasterApi.tsapp_set_can_channel_count(1)
        lin_ret = TSMasterApi.tsapp_set_lin_channel_count(0)
        if can_ret != 0 or lin_ret != 0:
            TSMasterApi.tsapp_del_mapping_verbose(APP_NAME.encode("utf8"), 0, 0)
            TSMasterApi.tsapp_set_can_channel_count(0)
            TSMasterApi.tsapp_set_lin_channel_count(0)
            can_ret = TSMasterApi.tsapp_set_can_channel_count(1)
            lin_ret = TSMasterApi.tsapp_set_lin_channel_count(0)
            if can_ret != 0 or lin_ret != 0:
                can_error = "OK" if can_ret == 0 else _format_ts_error(can_ret)
                lin_error = "OK" if lin_ret == 0 else _format_ts_error(lin_ret)
                raise ValueError(f"设置CAN通道数失败: can={can_error}; lin={lin_error}")
        # 获取参数
        channel_count: int = self.PRODUCTS[device_name]["channel_count"]
        sub_type: int = self.PRODUCTS[device_name]["sub_type"]
        is_canfd: bool = self.PRODUCTS[device_name]["fd"]
        # 检查参数
        if channel + 1 > channel_count:
            raise ValueError(f"改设备通道数为{channel_count}，通道数超出范围")
        if fd and not is_canfd:
            raise ValueError("设备不支持CAN FD模式")
        # 映射通道
        if (
                TSMasterApi.tsapp_set_mapping_verbose(
                    APP_NAME.encode("utf8"),
                    0,  # AAppChannelType  通道类型枚举值（如APP_CAN、APP_LIN）
                    0,  # AAppChannel  # 应用通道，从0开始
                    device_name.encode("UTF8"),  # 硬件设备名称（如 "TC1016"）
                    device_type,  # 硬件类型枚举值（如 TS_USB_DEVICE）
                    sub_type,  # AHardwareSubType  # 硬件子类型枚举值（如 TS_USB_DEVICE_SUBTYPE_TC1016）
                    hw_index,  # 硬件设备索引，从0开始
                    channel,  # 硬件通道，从0开始
                    True,  # 是否启用映射（True / False）
                )
                != 0
        ):
            raise ValueError(f"{channel}通道设置失败")
        else:
            log.debug(f"{channel}通道设置成功")    
        if fd:
            if 0 != TSMasterApi.tsapp_configure_baudrate_canfd(0, bitrate // 1000, data_bitrate // 1000, 1, 0, m120):
                raise ValueError("CAN FD参数设置失败")
            else:
                log.debug("CAN FD参数设置成功")
        else:
            if 0 != TSMasterApi.tsapp_configure_baudrate_can(0, bitrate // 1000, False, m120):
                raise ValueError("CAN参数设置失败")
            else:
                log.debug("CAN参数设置成功")
        if 0 != TSMasterApi.tsapp_connect():
            raise ValueError("can工具连接失败")
        else:
            if self.fifo_mode: # 开启fifo模式
                TSMasterApi.tsfifo_enable_receive_fifo()
                TSMasterApi.tsfifo_enable_receive_error_frames()
            log.debug("can工具连接成功")

        if not self.fifo_mode: # 使用注册回调函数
            def On_CAN_EVENT(OBJ, ACAN):
                gil_state = ctypes.pythonapi.PyGILState_Ensure()
                try:
                    dlc_byte = ACAN.contents.FDLC
                    arbitration_id = 0 if ACAN.contents.FIdentifier == -1 else ACAN.contents.FIdentifier
                    msg = can.Message(
                        is_fd=False,
                        timestamp=ACAN.contents.FTimeUs / 1000000,
                        is_extended_id=(ACAN.contents.FProperties >> 2 & 1) == 1,
                        arbitration_id=arbitration_id,
                        data=bytearray(ACAN.contents.FData[i] for i in range(dlc_byte)),
                        dlc=dlc_byte,
                        # channel=ACAN.contents.FIdxChn,
                        channel=self.channel,
                        is_remote_frame=(ACAN.contents.FProperties >> 1 & 1) == 1,
                        is_rx=(ACAN.contents.FProperties & 1) == 0,
                        is_error_frame=ACAN.contents.FProperties == 0x80,
                    )
                    if not self.receive_own_messages and not msg.is_rx:  # 鎺ュ彈鍙戦€佺殑娑堟伅
                        return
                    if self.id_filters:
                        if msg.arbitration_id in self.id_filters:
                            self.queue_recv.put(msg)
                    else:
                        self.queue_recv.put(msg)
                finally:
                    ctypes.pythonapi.PyGILState_Release(gil_state)

            def On_CANFD_EVENT(OBJ, ACANFD):
                gil_state = ctypes.pythonapi.PyGILState_Ensure()
                try:
                    dlc_byte = DLC2BYTE_LEN[ACANFD.contents.FDLC]
                    arbitration_id = 0 if ACANFD.contents.FIdentifier == -1 else ACANFD.contents.FIdentifier
                    msg = can.Message(
                        is_fd=ACANFD.contents.FFDProperties & 1 == 1,
                        bitrate_switch=ACANFD.contents.FFDProperties >> 1 & 1 == 1,
                        timestamp=ACANFD.contents.FTimeUs / 1000000,
                        is_extended_id=(ACANFD.contents.FProperties >> 2 & 1) == 1,
                        arbitration_id=arbitration_id,
                        data=bytearray(ACANFD.contents.FData[i] for i in range(dlc_byte)),
                        dlc=dlc_byte,
                        # channel=ACANFD.contents.FIdxChn,
                        channel=self.channel,
                        is_remote_frame=(ACANFD.contents.FProperties >> 1 & 1) == 1,
                        is_rx=(ACANFD.contents.FProperties & 1) == 0,
                        is_error_frame=ACANFD.contents.FProperties == 0x80,
                    )
                    if not self.receive_own_messages and not msg.is_rx:  # 鎺ュ彈鍙戦€佺殑娑堟伅
                        return
                    if self.id_filters:
                        if msg.arbitration_id in self.id_filters:
                            self.queue_recv.put(msg)
                    else:
                        self.queue_recv.put(msg)
                finally:
                    ctypes.pythonapi.PyGILState_Release(gil_state)
            # 回调事件
            if not fd:
                self.OnCANevent = TSMasterApi.TCANQueueEvent_Win32(On_CAN_EVENT)
                obj1 = TSMasterApi.c_int32(0)
                if 0 != TSMasterApi.tsapp_register_event_can(obj1, self.OnCANevent):
                    raise ValueError("注册CAN事件失败")
                else:
                    log.debug("注册CAN事件成功")
            else:
                self.OnCANFDevent = TSMasterApi.TCANFDQueueEvent_Win32(On_CANFD_EVENT)
                obj2 = TSMasterApi.c_int32(0)
                if 0 != TSMasterApi.tsapp_register_event_canfd(obj2, self.OnCANFDevent):
                    raise ValueError("注册CAN FD事件失败")
                else:
                    log.debug("注册CAN FD事件成功")
        self.lock_shutdown = Lock()
        self.channel_info = f"TSMaster: {device_name} ch:{channel} sn:{hw_sn}"
        super().__init__(
            channel=channel,
            can_filters=can_filters,
            **kwargs,
        )

    def send(self, msg: can.Message, timeout=None):
        if self.send_async_count >= 64:
            log.debug(f"当前异步队列数量{self.send_async_count}，同步发送消息，等待队列清空")
            send_canfd_func = lambda msg: TSMasterApi.tsapp_transmit_canfd_sync(msg, 1000)
            send_can_func = lambda msg: TSMasterApi.tsapp_transmit_can_sync(msg, 1000)
            self.send_async_count = 0
        else:
            send_canfd_func = TSMasterApi.tsapp_transmit_canfd_async
            send_can_func = TSMasterApi.tsapp_transmit_can_async
            self.send_async_count += 1
        if msg.is_fd:
            FDmsg = TSMasterApi.TLIBCANFD()
            if msg.bitrate_switch:
                FDmsg.FFDProperties = FDmsg.FFDProperties | 0x02
            else:
                FDmsg.FFDProperties = FDmsg.FFDProperties & (~0x02)
            if msg.is_extended_id:
                FDmsg.FProperties = FDmsg.FProperties | 0x04
            else:
                FDmsg.FProperties = FDmsg.FProperties & (~0x04)
            FDmsg.FIdentifier = msg.arbitration_id
            FData0, fd_dlc = _build_canfd_payload(msg)
            for i, data_byte in enumerate(FData0):
                FDmsg.FData[i] = data_byte
            FDmsg.FDLC = fd_dlc
            FDmsg.FIdxChn = 0
            if msg.is_remote_frame:
                FDmsg.FProperties = FDmsg.FProperties | 0x02
            else:
                FDmsg.FProperties = FDmsg.FProperties & (~0x02)
            send_canfd_func(FDmsg)
        else:
            msg_tosun = TSMasterApi.TLIBCAN()
            if msg.is_extended_id:
                msg_tosun.FProperties = msg_tosun.FProperties | 0x04
            else:
                msg_tosun.FProperties = msg_tosun.FProperties & (~0x04)
            msg_tosun.FIdentifier = msg.arbitration_id
            FData0 = bytearray(msg.data)
            len_FData0 = len(FData0)
            for i in range(len_FData0):
                msg_tosun.FData[i] = FData0[i]
            msg_tosun.FDLC = len_FData0
            msg_tosun.FIdxChn = 0
            if msg.is_remote_frame:
                msg_tosun.FProperties = msg_tosun.FProperties | 0x02
            else:
                msg_tosun.FProperties = msg_tosun.FProperties & (~0x02)
            send_can_func(msg_tosun)

    def _queue_message(self, msg: can.Message):
        if not self.receive_own_messages and not msg.is_rx:
            return

        if self._matches_filters(msg):
            self.queue_recv.put(msg)

    def receive_batch_frame(self):
        size = TSMasterApi.c_int32(1000)
        if not self.fd:
            r = TSMasterApi.tsfifo_receive_can_msgs(listcanmsg, size, 0, 1)
            if r != 0:
                raise ValueError(f"接收CAN消息失败，错误码：{r}")
            for i in range(size.value):
                ACAN = listcanmsg[i]
                dlc_byte = ACAN.contents.FDLC
                arbitration_id = 0 if ACAN.contents.FIdentifier == -1 else ACAN.contents.FIdentifier
                msg = can.Message(
                    is_fd=False,
                    timestamp=ACAN.contents.FTimeUs / 1000000,
                    is_extended_id=(ACAN.contents.FProperties >> 2 & 1) == 1,
                    arbitration_id=arbitration_id,
                    data=bytearray(ACAN.contents.FData[i] for i in range(dlc_byte)),
                    dlc=dlc_byte,
                    # channel=ACAN.contents.FIdxChn,
                    channel=self.channel,
                    is_remote_frame=(ACAN.contents.FProperties >> 1 & 1) == 1,
                    is_rx=(ACAN.contents.FProperties & 1) == 0,
                    is_error_frame=ACAN.contents.FProperties == 0x80,
                )
                self._queue_message(msg)
        else:
            r = TSMasterApi.tsfifo_receive_canfd_msgs(listcanfdmsg, size, 0, 1)
            if r != 0:
                raise ValueError(f"接收CAN消息失败，错误码：{r}")
            for i in range(size.value):
                ACANFD = listcanfdmsg[i]
                dlc_byte = DLC2BYTE_LEN[ACANFD.FDLC]
                arbitration_id = 0 if ACANFD.FIdentifier == -1 else ACANFD.FIdentifier
                msg = can.Message(
                    is_fd=ACANFD.FFDProperties & 1 == 1,
                    bitrate_switch=ACANFD.FFDProperties >> 1 & 1 == 1,
                    timestamp=ACANFD.FTimeUs / 1000000,
                    is_extended_id=(ACANFD.FProperties >> 2 & 1) == 1,
                    arbitration_id=arbitration_id,
                    data=bytearray(ACANFD.FData[i] for i in range(dlc_byte)),
                    dlc=dlc_byte,
                    # channel=ACANFD.FIdxChn,
                    channel=self.channel,
                    is_remote_frame=(ACANFD.FProperties >> 1 & 1) == 1,
                    is_rx=(ACANFD.FProperties & 1) == 0,
                    is_error_frame=ACANFD.FProperties == 0x80,
                )
                self._queue_message(msg)

    def _recv_internal(self, timeout=None):
        if self.fifo_mode:
            if self.queue_recv.qsize() > 0:
                return self.queue_recv.get(), bool(self._filters)
            start_time = time.perf_counter()
            while True:
                with self.lock_shutdown:
                    if self._is_shutdown:
                        break
                    self.receive_batch_frame()
                if self.queue_recv.qsize() > 0:
                    return self.queue_recv.get(), bool(self._filters)
                if time.perf_counter() - start_time > timeout:
                    break
                time.sleep(0.001)
            return None, bool(self._filters)
        else:
            try:
                return self.queue_recv.get(timeout=timeout), bool(self._filters)
            except Empty:
                return None, bool(self._filters)

    def _apply_filters(self, filters):
        self.id_filters = filters

    def shutdown(self):
        with self.lock_shutdown:
            log.debug('关闭BUS')
            super().shutdown()
        log.debug('断开TSMaster连接')
        TSMasterApi.tsapp_disconnect()
        time.sleep(3.5)
        TSMasterApi.tsapp_del_mapping_verbose(APP_NAME.encode("utf8"), 0, 0)

    @classmethod
    def _detect_available_configs(cls):
        """获取同星USB硬件列表"""
        log.debug('初始化TSMaster DLL调用')
        _activate_current_application()
        confs = []
        # 获取硬件列表
        ACount = TSMasterApi.c_int32(0)
        rt = TSMasterApi.tsapp_enumerate_hw_devices(ACount)
        if rt != 0:
            log.error(f"TSMaster获取硬件列表失败：{rt}")
            return confs
        PTLIBHWInfo = TSMasterApi.TLIBHWInfo()
        for i in range(ACount.value):
            TSMasterApi.tsapp_get_hw_info_by_index(i, PTLIBHWInfo)
            vendor_name = PTLIBHWInfo.FVendorName.decode("utf8")
            device_type = PTLIBHWInfo.FDeviceType
            if not all(
                    [
                        any(
                            [
                                "TOSUN" in vendor_name.upper(),
                                vendor_name == 'TC1055Pro',  # ugly fix, but works, because of the stupid TC1055Pro
                            ]
                        ),
                        device_type in (3, 10, 14),  # 只允许同星USB/wifi设备
                    ]
            ):
                continue
            device_name = PTLIBHWInfo.FDeviceName.decode("utf8")
            for _device_name in cls.PRODUCTS.keys():
                if device_name.replace(" ", "").upper() in _device_name.upper():
                    device_name = _device_name
                    break
            device_index = PTLIBHWInfo.FDeviceIndex  # 多个同型号设备索引
            device_properties = cls.PRODUCTS[device_name]
            device_sn = PTLIBHWInfo.FSerialString.decode("utf8")
            for i in range(device_properties["channel_count"]):
                confs.append(
                    dict(
                        interface="tosun",
                        device_name=device_name,
                        name=f"{vendor_name} {device_name} {device_index + 1} {'CAN FD' if device_properties['fd'] else 'CAN'} 通道{i + 1} ({device_sn})",
                        **device_properties,
                        device_type=device_type,
                        channel=i,
                        sn=device_sn,
                        index=device_index,
                    )
                )
        return confs
