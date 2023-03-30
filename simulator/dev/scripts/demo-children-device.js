/**
 * 烟感设备模拟器
 */
var _logger = logger;

//事件类型
var events = {
    reportProperty: function (index, session) {
        var deviceId = "test-child-1";
        var topic = "/children/report-property";
        var json = JSON.stringify({
            "deviceId": deviceId,
            "success": true,
            "timestamp": new Date().getTime(),
            properties: {"temperature": java.util.concurrent.ThreadLocalRandom.current().nextDouble(20, 40)},
        });
        session.sendMessage(topic, json)
    },
    fireAlarm: function (index, session) {
        var deviceId = "test-child-1";
        var topic = "/children/fire_alarm/department/1/area/1/dev/" + deviceId;
        var json = JSON.stringify({
            "deviceId": deviceId, // 设备编号 "pid": "TBS-110", // 设备编号
            "a_name": "商务大厦", // 区域名称 "bid": 2, // 建筑 ID
            "b_name": "C2 栋", // 建筑名称
            "l_name": "12-05-201", // 位置名称
            "timestamp": new Date().getTime() // 消息时间
        });

        session.sendMessage(topic, json)
    }
};

//事件上报
simulator.onEvent(function (index, session) {
    //上报属性
    events.reportProperty(index, session);

    //上报火警
    events.fireAlarm(index, session);
});

simulator.bindHandler("/children/read-property", function (message, session) {
    _logger.info("读取属性:[{}]", message);
    session.sendMessage("/children/read-property-reply", JSON.stringify({
        messageId: message.messageId,
        deviceId: message.deviceId,
        timestamp: new Date().getTime(),
        properties: {"temperature": java.util.concurrent.ThreadLocalRandom.current().nextDouble(20, 40)},
        success: true
    }));
});

simulator.bindHandler("/read-property", function (message, session) {
    _logger.info("读取属性:[{}]", message);
    session.sendMessage("/children/read-property-reply", JSON.stringify({
        messageId: message.messageId,
        deviceId: message.deviceId,
        timestamp: new Date().getTime(),
        properties: {"temperature": java.util.concurrent.ThreadLocalRandom.current().nextDouble(20, 40)},
        success: true
    }));
});


simulator.onConnect(function (session) {
    //模拟子设备上线
    session.sendMessage("/children/device_online_status", JSON.stringify({
        deviceId: "test61423",
        timestamp: new Date().getTime(),
        status: "1",
        success: true
    }));

    simulator.runDelay(function () {

        session.sendMessage("/children/device_online_status", JSON.stringify({
            deviceId: "test61423",
            timestamp: new Date().getTime(),
            status: "0",
            success: true
        }));

    },1000)


});

simulator.onAuth(function (index, auth) {
    //使用网关设备id 连接平台
    auth.setClientId("gateway-" + index);
    auth.setUsername("admin");
    auth.setPassword("admin");
});