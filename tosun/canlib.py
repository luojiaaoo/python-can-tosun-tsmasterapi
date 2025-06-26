import logging
import time
from collections import defaultdict
from queue import Queue, Empty
from typing import List

import can
from can import BusABC
from . import TSMasterApi

log = logging.getLogger("can.TSMasterApi")
log.setLevel(logging.DEBUG)
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


class TSMasterApiBus(BusABC):
    _PRODUCTS = {
        "TC1001": {"fd": False, "channel_count": 1, "sub_type": 3, "device_type": 3},
        "TC1011": {"fd": True, "channel_count": 1, "sub_type": 5, "device_type": 3},
        "TC1014": {"fd": True, "channel_count": 4, "sub_type": 8, "device_type": 3},
        "TC1026": {"fd": True, "channel_count": 1, "sub_type": 10, "device_type": 3},
        "TC1016": {"fd": True, "channel_count": 4, "sub_type": 11, "device_type": 3},
        "TC1012": {"fd": True, "channel_count": 1, "sub_type": 12, "device_type": 3},
        "TC1013": {"fd": True, "channel_count": 2, "sub_type": 13, "device_type": 3},
        "Tlog1002": {"fd": True, "channel_count": 2, "sub_type": 14, "device_type": 3},
        "TC1034": {"fd": True, "channel_count": 2, "sub_type": 15, "device_type": 3},
        "TC1018": {"fd": True, "channel_count": 12, "sub_type": 16, "device_type": 3},
        "MP1013": {"fd": True, "channel_count": 2, "sub_type": 19, "device_type": 3}, # pcie
        "TC1113": {"fd": True, "channel_count": 2, "sub_type": 20, "device_type": 10}, # wifi
        "TC1114": {"fd": True, "channel_count": 4, "sub_type": 21, "device_type": 10},  # wifi
        "TP1013": {"fd": True, "channel_count": 2, "sub_type": 22, "device_type": 3},  # pcie
        "TC1017": {"fd": True, "channel_count": 8, "sub_type": 23, "device_type": 3},
        "TP1018": {"fd": True, "channel_count": 12, "sub_type": 24, "device_type": 3}, # pcie
        "Tlog1004": {"fd": True, "channel_count": 4, "sub_type": 26, "device_type": 3},
        "TP1034": {"fd": True, "channel_count": 2, "sub_type": 29, "device_type": 3},  # pcie
        "TP1026": {"fd": True, "channel_count": 1, "sub_type": 31, "device_type": 3},  # pcie
    }
    PRODUCTS = defaultdict(lambda: {"fd": True, "channel_count": 1, "sub_type": 0, "device_type": 3}, _PRODUCTS)

    def __init__(
            self,
            channel: int,
            device_name: str,  # 设备名
            device_type: int,  # 硬件类型
            hw_index: int,  # 设备索引，用于区分同型号设备，从0开始
            fd: bool = True,
            bitrate: int = 500000,
            data_bitrate: int = 2000000,
            receive_own_messages: bool = False,
            can_filters: List[int] = None,
            m120: bool = False,  # 是否开启120欧姆终端电阻
            **kwargs,
    ):
        self.channel = channel
        self.device_name = device_name
        self.device_type = device_type
        self.hw_index = hw_index
        self.m120 = m120
        self.queue_recv = Queue()
        self.send_async_count = 0
        self.id_filters = None
        self.receive_own_messages = receive_own_messages
        # 初始化应用名，每个通道有唯一名
        self.app_name_plus = f"{APP_NAME}_{channel}"

        def On_CAN_EVENT(OBJ, ACAN):
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
            if not self.receive_own_messages and not msg.is_rx:  # 接受发送的消息
                return
            if self.id_filters:
                if msg.arbitration_id in self.id_filters:
                    self.queue_recv.put(msg)
            else:
                self.queue_recv.put(msg)

        def On_CANFD_EVENT(OBJ, ACANFD):
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
            if not self.receive_own_messages and not msg.is_rx:  # 接受发送的消息
                return
            if self.id_filters:
                if msg.arbitration_id in self.id_filters:
                    self.queue_recv.put(msg)
            else:
                self.queue_recv.put(msg)

        # 回调事件
        self.OnCANevent = TSMasterApi.TCANQueueEvent_Win32(On_CAN_EVENT)
        self.OnCANFDevent = TSMasterApi.TCANFDQueueEvent_Win32(On_CANFD_EVENT)
        # 开始初始化硬件
        log.debug('初始化DLL')
        TSMasterApi.initialize_lib_tsmaster(self.app_name_plus.encode("utf8"))
        # 获取参数
        channel_count: int = self.PRODUCTS[device_name]["channel_count"]
        sub_type: int = self.PRODUCTS[device_name]["sub_type"]
        is_canfd: bool = self.PRODUCTS[device_name]["fd"]
        # 检查参数
        if channel + 1 > channel_count:
            raise ValueError(f"改设备通道数为{channel_count}，通道数超出范围")
        if fd and not is_canfd:
            raise ValueError("设备不支持CAN FD模式")
        if TSMasterApi.tsapp_set_can_channel_count(1) != 0 or TSMasterApi.tsapp_set_lin_channel_count(0) != 0:
            raise ValueError("设置CAN通道数失败")
        else:
            count = TSMasterApi.c_int32(0)
            TSMasterApi.tsapp_get_can_channel_count(count)
            log.debug(f"应用设置CAN通道数：{count.value}")
            TSMasterApi.tsapp_set_lin_channel_count(0)
            log.debug('设置CAN通道数成功')
        # 映射通道
        if (
                TSMasterApi.tsapp_set_mapping_verbose(
                    self.app_name_plus.encode("utf8"),
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
            if 0 != TSMasterApi.tsapp_configure_baudrate_can(0, bitrate, False, m120):
                raise ValueError("CAN参数设置失败")
            else:
                log.debug("CAN参数设置成功")
        TSMasterApi.tsfifo_enable_receive_error_frames()
        if 0 != TSMasterApi.tsapp_connect():
            raise ValueError("can工具连接失败")
        else:
            log.debug("can工具连接成功")

        obj1 = TSMasterApi.c_int32(0)
        obj2 = TSMasterApi.c_int32(0)
        if 0 != TSMasterApi.tsapp_register_event_can(obj1, self.OnCANevent):
            raise ValueError("注册CAN事件失败")
        else:
            log.debug("注册CAN事件成功")
        if fd:
            if 0 != TSMasterApi.tsapp_register_event_canfd(obj2, self.OnCANFDevent):
                raise ValueError("注册CAN FD事件失败")
            else:
                log.debug("注册CAN FD事件成功")
        super().__init__(
            channel=channel,
            can_filters=can_filters,
            **kwargs,
        )

    def send(self, msg: can.Message, timeout=None):
        log.debug(f"准备发送消息：{msg}")
        if self.send_async_count > 512:
            send_canfd_func = lambda msg: TSMasterApi.tsapp_transmit_canfd_sync(msg, 100)
            send_can_func = lambda msg: TSMasterApi.tsapp_transmit_can_sync(msg, 100)
            self.send_async_count = 0
        else:
            send_canfd_func = TSMasterApi.tsapp_transmit_canfd_async
            send_can_func = TSMasterApi.tsapp_transmit_can_async
            self.send_async_count += 1
        if msg.is_fd:
            FDmsg = TSMasterApi.TLIBCANFD()
            if msg.bitrate_switch:
                FDmsg.FProperties = FDmsg.FFDProperties | 0x02
            else:
                FDmsg.FProperties = FDmsg.FFDProperties & (~0x02)
            if msg.is_extended_id:
                FDmsg.FProperties = FDmsg.FProperties | 0x04
            else:
                FDmsg.FProperties = FDmsg.FProperties & (~0x04)
            FDmsg.FIdentifier = msg.arbitration_id
            FData0 = bytearray(msg.data)
            len_FData0 = len(FData0)
            for i in range(len_FData0):
                FDmsg.FData[i] = FData0[i]
            FDmsg.FDLC = BYTE_LEN2DLC[len_FData0]
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

    def _recv_internal(self, timeout=None):
        try:
            return self.queue_recv.get(timeout=timeout), bool(self.id_filters)
        except Empty:
            return None, bool(self.id_filters)

    def _apply_filters(self, filters):
        self.id_filters = filters

    def shutdown(self):
        log.debug('关闭BUS')
        super().shutdown()
        log.debug('断开TSMaster连接')
        TSMasterApi.tsapp_disconnect()
        log.debug('中止TSMaster DLL调用')
        TSMasterApi.finalize_lib_tsmaster()

    @classmethod
    def _detect_available_configs(cls):
        """获取同星USB硬件列表"""
        confs = []
        TSMasterApi.initialize_lib_tsmaster(APP_NAME.encode("utf8"))  # 初始化应用
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
            if not (vendor_name == "TOSUN" and PTLIBHWInfo.FDeviceType in (3, 10)):  # 只允许同星USB/wifi设备
                continue
            device_name = PTLIBHWInfo.FDeviceName.decode("utf8")
            for _device_name in cls.PRODUCTS.keys():
                if device_name.upper() in _device_name.upper():
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
                        channel=i,
                        sn=device_sn,
                        index=device_index,
                    )
                )
        TSMasterApi.finalize_lib_tsmaster()
        return confs


if __name__ == "__main__":
    print(TSMasterApiBus._detect_available_configs())
    a = TSMasterApiBus(device_name="TC1016", device_type=3, hw_index=0, channel=2)
    for i in range(100):
        msg = can.Message(arbitration_id=0x7DF, data=[0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01], is_extended_id=False)
        a.send(msg)
        TSMasterApi.tsapp_transmit_canfd_async(TSMasterApi.TLIBCANFD(FIdentifier=0x101, FData=[0, 1, 2, 3, 4, 5, 6, 7]))
    print(a.recv())
    time.sleep(2)
    a.shutdown()
