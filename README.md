# python-can-tosun-tsmasterapi

TOSUN同星软件接口TSMasterApi的python-can适配驱动，已测试TC1016P

## 安装

通过 python-can 的插件机制，无需修改 python-can 源代码，`pip install` 即可使用。

```bash
# 从源码安装（开发模式）
cd python-can-tosun-tsmasterapi
pip install -e .

# 或直接安装
pip install .
```

安装后，`tosun` 接口将自动注册到 python-can 中，可直接通过 `interface="tosun"` 使用。

## example

```python
import can

# 方式一：直接指定 interface="tosun"
bus = can.Bus(interface='tosun', channel=0, fd=True, bitrate=500000, data_bitrate=2000000,
              receive_own_messages=True, can_filters=[0x111, 0x222], m120=True,
              device_name='TC1016', device_type=3, hw_sn='', hw_index=0)

msg = can.Message(arbitration_id=0x111,
                  data=[0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
                  is_extended_id=False)
bus.send(msg)

while (rec := bus.recv(timeout=0.1)):
    print(rec)

bus.shutdown()
```

```python
# 方式二：通过配置文件
# 在 can.rc 或环境变量中设置:
#   [default]
#   interface = tosun
#   channel = 0
import can
bus = can.Bus()
```

## 扫描可用设备

```python
import can
configs = can.detect_available_configs(interfaces=["tosun"])
for config in configs:
    print(config)
```

## 历史问题

1. canfd报文设置brs标志位后，发送的报文未开启可变波特率，暂未查出原因，已解决
   
2. `已解决`: 在一个进程中，只能使用一个通道，分析其原因，可能因为DLL只加载一次，TSMasterApi的接口不像硬件接口一样绑定Handle去操作通道，这个问题可能需要多次加载DLL去解决
   
    > `已通过多进程解决`
