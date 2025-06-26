# python-can-tosun-tsmasterapi

TOSUN同星软件接口TSMasterApi的python-can适配驱动，已测试TC1016P
1. 修改python-can路径下的can/interfaces/__init__.py文件, 在BACKENDS字典中添加一行:

   ```
   "tosun": ("can.interfaces.tosun", "TSMasterApiBus"),
   ```

2. 将tosun文件夹拷贝到can/interfaces/文件夹下

## example

```python
import can
can_filters = [0x111, 0x222]
bus = can.interface.Bus(bustype='tosun', channel=0, fd=True, bitrate=500000, data_bitrate=2000000,
                            receive_own_messages=True, can_filters=can_filters, m120=True, device_name='TC1016', device_type=3, hw_index=0)
msg = can.Message(arbitration_id=0x111,data=[0x02, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],is_extended_id=False, )
bus.send(msg)
while (rec:=bus.recv(timeout=0.1)):
    print(rec)
bus.shutdown()
```

## 待解决

1. canfd报文设置brs标志位后，发送的报文未开启可变波特率，暂未查出原因
   
2. 在一个进程中，只能使用一个通道，分析其原因，可能因为DLL只加载一次，TSMasterApi的接口不像硬件接口一样绑定Handle去操作通道，这个问题可能需要多次加载DLL去解决，TODO...
