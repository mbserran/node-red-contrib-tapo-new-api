# node-red-contrib-tplink-tapo-connect-api

Unofficial node-RED node for connecting to TP-Link Tapo devices. Currently limited to the P100 & P105 smart plugs and L510E smart bulbs.

![node](./figs/sample00.png)

## nodes

- toggle

    ![node-command](figs/node-toggle.png)

    This node module provides the ability to toggle (on / off) the power of tapo smart plugs.

- turn-on

    ![node-command](figs/node-turn-on.png)

    This node module provides the ability to power on tapo smart plugs.

- turn-off

    ![node-command](figs/node-turn-off.png)

    This node module provides the ability to power off tapo smart plugs.

- brightness

    ![node-brightness](figs/node-brightness.png)

    This node module provides the ability to set the brightness of tapo smart bulbs.

- colour

    ![node-command](figs/node-colour.png)

    This node module provides the ability to set the color of tapo smart bulbs.

- command

    ![node-command](figs/node-command.png)

    This node module provides several features by input `"msg.payload.command"`.

    1. power

        tapo device power on/off

        `msg.payload.option`

        ```cmd
        0: tapo device power off
        1: tapo device power on
        ```

    2. toggle

        tapo device power on/off(toggle)

    3. status

        get tapo device info

- status

    ![node-command](figs/node-status.png)

    This node module provides the ability to get the device infomation of tapo smart plugs.

    Get the device information from `"output: msg.payload.tapoDeviceInfo"`.

- tplink_tapo_connect_api(`deprecated`)

    ![node-command](figs/tplink_tapo_connect_api.png)

    This "node module: tplink_tapo_connect_api" has been left for compatibility, this module may be deleted without notice.

## Pre-requisites

The node-red-contrib-tplink-tapo-connect-api requires `Node-RED 1.00` to be installed.

## Install

```cmd
npm install node-red-contrib-tplink-tapo-connect-api
```

## Usage

- Properties

  ![config](./figs/sample01.png)

  - Name

    Set the node name displayed in the flow.

  - Email

    Set the email address registered with Tp Link.

  - Password

    Set the password registered with Tp Link.

  - Search mode

    Select a search mode for the tapo device.

    [Usage]
    - ip : search by ip. (It's fast.)
    - alias: search by alias and ip range.

  - Tapo ipaddress(`selected: ip`)

    Set the IP address to the Tapo device.

  - Tapo alias(`selected: alias`)

    set the tapo device alias registered with Tp Link.

  - Tapo find ip range(`selected: alias`)

    set the IP range to search for Tapo device.

    [Usage]
    - case1: "192.168.0.1 to 192.168.0.25"
    - case2: "192.168.0.0/24"

### Inputs

`msg.payload`

```typescript
type searchModeTypes = "ip" | "alias";
type commandTypes = "" | "power" | "toggle" | "status";

type payload {
    email: string;
    password: string;
    deviceIp: string;
    deviceAlias: string;
    deviceIpRange: string;
    searchMode : searchModeTypes;
    command: commandTypes;          /* "node-command" only */
    option: {                       /* "node-command" only */
        power?: number;
    };
    colour: string;                 /* "node-colour" only */
    brightness: numbar;             /* "node-brightness" only */
}
```

[example1]

```json
msg = {
  "email": "your@gmail.com",
  "password": "password",
  "deviceIp": "192.168.0.xxx",
  "command": "power",
  "option": {
    "power": 0
  }
}
```

[example2]

```json
msg = {
  "email": "your@gmail.com",
  "password": "password",
  "deviceIp": "192.168.0.xxx",
  "command": "toggle"
}
```

### Outputs

The processing result is passed by msg.payload. It consists of an object that contains the following properties:

```typescript
type tapoConnectResults = {
    result: boolean; /* true: success, false: failure */
    tapoDeviceInfo?: tapoDeviceInfo; /* smart plug device infomation */
    errorInf?: Error;
}
```

[smart plug device infomation]

You can tell if the device is on or off by getting "device_on".

```text
true: smart plug power on
false: smart plug power off
```

```javascript
{
    result: true,
    tapoDeviceInfo: {
    device_id: "*************"
    fw_ver: "1.2.10 Build 20200609 Rel. 33394"
    hw_ver: "1.0.0"
    type: "SMART.TAPOPLUG"
    model: "P105"
    mac: "XX-XX-XX-XX-XX-XX"
    hw_id: "*************"
    fw_id: "*************"
    oem_id: "*************"
    specs: "JP"
    device_on: false
    on_time: 0
    overheated: false
    nickname: "3d printer power supply"
    location: "XXXXXXXXXXXXXXXX"
    avatar: "plug"
    time_usage_today: 0
    time_usage_past7: 0
    time_usage_past30: 0
    longitude: 0
    latitude: 0
    has_set_location_info: true
    ip: "192.168.0.XXX"
    ssid: "SSID"
    signal_level: 0
    rssi: 0
    region: "Asia/Tokyo"
    time_diff: 0
    lang: "ja_JP"
    }
}
```

### example

```json
[
    {
        "id": "01ccda01ada3740d",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "9688311d857cbbd4",
            "13d4a967f251539e",
            "d93c8ed65cee8445",
            "41d054e7f0db6c7d"
        ],
        "x": 34,
        "y": 19,
        "w": 652,
        "h": 142
    },
    {
        "id": "9688311d857cbbd4",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "01ccda01ada3740d",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 570,
        "y": 120,
        "wires": []
    },
    {
        "id": "13d4a967f251539e",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "01ccda01ada3740d",
        "name": "",
        "props": [],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 190,
        "y": 120,
        "wires": [
            [
                "41d054e7f0db6c7d"
            ]
        ]
    },
    {
        "id": "d93c8ed65cee8445",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "01ccda01ada3740d",
        "name": "[node-turn-off]",
        "info": "",
        "x": 130,
        "y": 60,
        "wires": []
    },
    {
        "id": "41d054e7f0db6c7d",
        "type": "tplink_turn_off",
        "z": "35250d14.0fb0b2",
        "g": "01ccda01ada3740d",
        "name": "",
        "deviceIp": "192.168.0.122",
        "deviceAlias": "",
        "deviceIpRange": "",
        "searchMode": "ip",
        "x": 380,
        "y": 120,
        "wires": [
            [
                "9688311d857cbbd4"
            ]
        ]
    },
    {
        "id": "06b6360f81296af7",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "2ee76b9b2c3cc22d",
            "c76158138c91c20f",
            "99d557cc9c7c0fe5",
            "6e0f6bd8b59f15b8",
            "1d16de9bc2fc9db5"
        ],
        "x": 34,
        "y": 379,
        "w": 652,
        "h": 202
    },
    {
        "id": "2ee76b9b2c3cc22d",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "06b6360f81296af7",
        "name": "100",
        "props": [
            {
                "p": "payload.brightness",
                "v": "100",
                "vt": "num"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 190,
        "y": 540,
        "wires": [
            [
                "1d16de9bc2fc9db5"
            ]
        ]
    },
    {
        "id": "c76158138c91c20f",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "06b6360f81296af7",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 570,
        "y": 480,
        "wires": []
    },
    {
        "id": "99d557cc9c7c0fe5",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "06b6360f81296af7",
        "name": "0",
        "props": [
            {
                "p": "payload.brightness",
                "v": "0",
                "vt": "num"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 190,
        "y": 480,
        "wires": [
            [
                "1d16de9bc2fc9db5"
            ]
        ]
    },
    {
        "id": "6e0f6bd8b59f15b8",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "06b6360f81296af7",
        "name": "[node-brightness]",
        "info": "",
        "x": 140,
        "y": 420,
        "wires": []
    },
    {
        "id": "1d16de9bc2fc9db5",
        "type": "tplink_brightness",
        "z": "35250d14.0fb0b2",
        "g": "06b6360f81296af7",
        "name": "",
        "deviceIp": "192.168.0.122",
        "deviceAlias": "",
        "deviceIpRange": "",
        "searchMode": "ip",
        "brightness": "80",
        "x": 390,
        "y": 480,
        "wires": [
            [
                "c76158138c91c20f"
            ]
        ]
    },
    {
        "id": "086d3450b3d9dbd2",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "3404f36bd650ed10",
            "cdab8da9d33add5e",
            "94b3d0d0d8874cd5",
            "d2be7d3d82d57bab"
        ],
        "x": 714,
        "y": 199,
        "w": 632,
        "h": 142
    },
    {
        "id": "3404f36bd650ed10",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "086d3450b3d9dbd2",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 1230,
        "y": 300,
        "wires": []
    },
    {
        "id": "cdab8da9d33add5e",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "086d3450b3d9dbd2",
        "name": "",
        "props": [],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 850,
        "y": 300,
        "wires": [
            [
                "d2be7d3d82d57bab"
            ]
        ]
    },
    {
        "id": "94b3d0d0d8874cd5",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "086d3450b3d9dbd2",
        "name": "[node-status]",
        "info": "",
        "x": 810,
        "y": 240,
        "wires": []
    },
    {
        "id": "d2be7d3d82d57bab",
        "type": "tplink_status",
        "z": "35250d14.0fb0b2",
        "g": "086d3450b3d9dbd2",
        "name": "",
        "deviceIp": "192.168.0.122",
        "deviceAlias": "",
        "deviceIpRange": "",
        "searchMode": "ip",
        "x": 1030,
        "y": 300,
        "wires": [
            [
                "3404f36bd650ed10"
            ]
        ]
    },
    {
        "id": "4a73621dbd59ed57",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "2705cf801d2ce67f",
            "652a90197f7e9fa8",
            "0d09174cf7cb7b57",
            "540ce7bb94fbee5b",
            "8a3bb671c9d1af16",
            "62493963889dc648",
            "b5424b08cd6f0b05",
            "68ac8d3c198d8364",
            "3f8eab24d64abe2a",
            "28a412c037bbab85",
            "d14bd2a50a0e9e13",
            "4731fb8d1424c9ab",
            "57aae3e37c7efdc8",
            "9615b09994d298e1",
            "7f00d365e09bff33"
        ],
        "x": 34,
        "y": 619,
        "w": 652,
        "h": 422
    },
    {
        "id": "2705cf801d2ce67f",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 170,
        "y": 840,
        "wires": [
            [
                "d14bd2a50a0e9e13"
            ]
        ]
    },
    {
        "id": "652a90197f7e9fa8",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 570,
        "y": 840,
        "wires": []
    },
    {
        "id": "0d09174cf7cb7b57",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 170,
        "y": 760,
        "wires": [
            [
                "28a412c037bbab85"
            ]
        ]
    },
    {
        "id": "540ce7bb94fbee5b",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "tapo device infomation",
        "info": "",
        "x": 160,
        "y": 960,
        "wires": []
    },
    {
        "id": "8a3bb671c9d1af16",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "power on",
        "info": "",
        "x": 140,
        "y": 720,
        "wires": []
    },
    {
        "id": "62493963889dc648",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 170,
        "y": 1000,
        "wires": [
            [
                "4731fb8d1424c9ab"
            ]
        ]
    },
    {
        "id": "b5424b08cd6f0b05",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "power off",
        "info": "",
        "x": 140,
        "y": 800,
        "wires": []
    },
    {
        "id": "68ac8d3c198d8364",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "[node-command]",
        "info": "",
        "x": 140,
        "y": 660,
        "wires": []
    },
    {
        "id": "3f8eab24d64abe2a",
        "type": "tplink_command",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "deviceIp": "192.168.0.122",
        "deviceAlias": "",
        "deviceIpRange": "",
        "searchMode": "ip",
        "x": 560,
        "y": 760,
        "wires": [
            [
                "652a90197f7e9fa8"
            ]
        ]
    },
    {
        "id": "28a412c037bbab85",
        "type": "template",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "field": "payload",
        "fieldType": "msg",
        "format": "json",
        "syntax": "plain",
        "template": "{\n    \"email\": \"your@gmail.com\",\n    \"password\": \"password\",\n    \"deviceIp\": \"192.168.0.122\",\n    \"searchMode\": \"ip\",\n    \"command\": \"power\",\n    \"option\": {\n        \"power\": 1\n    }\n}",
        "output": "json",
        "x": 340,
        "y": 760,
        "wires": [
            [
                "3f8eab24d64abe2a"
            ]
        ]
    },
    {
        "id": "d14bd2a50a0e9e13",
        "type": "template",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "field": "payload",
        "fieldType": "msg",
        "format": "json",
        "syntax": "plain",
        "template": "{\n    \"email\": \"your@gmail.com\",\n    \"password\": \"foo\",\n    \"deviceAlias\": \"bar\",\n    \"deviceIpRange\": \"192.168.0.0/24\",\n    \"searchMode\": \"alias\",\n    \"command\": \"power\",\n    \"option\": {\n        \"power\": 0\n    }\n}",
        "output": "json",
        "x": 340,
        "y": 840,
        "wires": [
            [
                "3f8eab24d64abe2a"
            ]
        ]
    },
    {
        "id": "4731fb8d1424c9ab",
        "type": "template",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "field": "payload",
        "fieldType": "msg",
        "format": "json",
        "syntax": "plain",
        "template": "{\n    \"command\": \"status\"\n}",
        "output": "json",
        "x": 340,
        "y": 1000,
        "wires": [
            [
                "3f8eab24d64abe2a"
            ]
        ]
    },
    {
        "id": "57aae3e37c7efdc8",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "power on/off(toggle)",
        "info": "",
        "x": 170,
        "y": 880,
        "wires": []
    },
    {
        "id": "9615b09994d298e1",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 170,
        "y": 920,
        "wires": [
            [
                "7f00d365e09bff33"
            ]
        ]
    },
    {
        "id": "7f00d365e09bff33",
        "type": "template",
        "z": "35250d14.0fb0b2",
        "g": "4a73621dbd59ed57",
        "name": "",
        "field": "payload",
        "fieldType": "msg",
        "format": "json",
        "syntax": "plain",
        "template": "{\n    \"command\": \"toggle\"\n}",
        "output": "json",
        "x": 340,
        "y": 920,
        "wires": [
            [
                "3f8eab24d64abe2a"
            ]
        ]
    },
    {
        "id": "7b2634e685c20aa0",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "f5a5e8026b113f41",
            "72771d09395e2f3c",
            "a20995f2e443db2c",
            "1295d338c03939ee"
        ],
        "x": 34,
        "y": 199,
        "w": 652,
        "h": 142
    },
    {
        "id": "f5a5e8026b113f41",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "7b2634e685c20aa0",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 570,
        "y": 300,
        "wires": []
    },
    {
        "id": "72771d09395e2f3c",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "7b2634e685c20aa0",
        "name": "",
        "props": [],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 190,
        "y": 300,
        "wires": [
            [
                "1295d338c03939ee"
            ]
        ]
    },
    {
        "id": "a20995f2e443db2c",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "7b2634e685c20aa0",
        "name": "[node-toggle]",
        "info": "",
        "x": 130,
        "y": 240,
        "wires": []
    },
    {
        "id": "1295d338c03939ee",
        "type": "tplink_toggle",
        "z": "35250d14.0fb0b2",
        "g": "7b2634e685c20aa0",
        "name": "",
        "deviceIp": "192.168.0.122",
        "deviceAlias": "",
        "deviceIpRange": "",
        "searchMode": "ip",
        "x": 370,
        "y": 300,
        "wires": [
            [
                "f5a5e8026b113f41"
            ]
        ]
    },
    {
        "id": "82788920509ba58a",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "069f85ce6d806e2e",
            "31c719dd2c3a5f36"
        ],
        "x": 32,
        "y": 1567,
        "w": 2220,
        "h": 926
    },
    {
        "id": "069f85ce6d806e2e",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "82788920509ba58a",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "46c48181436a8401",
            "9d37bc800fb1537f",
            "1b74c9688b25f8e7",
            "ceaf2b9baccbf204",
            "d51d12589b13b79b",
            "23161dd53d6f0e38",
            "af53f24a391d3e82",
            "c65dc6c503b12dd1",
            "83c32f2e6da79559",
            "15983d3f7b9cb580",
            "351729dc09ee9cdc",
            "502269dee466779f",
            "8877a2a4303de95a",
            "efd87ba8bab74f92",
            "ba6386b9c4c4f60e",
            "6e933165ce8110ce",
            "b0fb1f214ac60aba",
            "342d853950376117",
            "73c74cf46b637ec7",
            "0e71ce5efe9543d5",
            "b6c863060a07feb4",
            "5f3c056c6dc2b576",
            "5167d005832b56c3",
            "2be21dc35de4d0a1",
            "3394762f76513829",
            "52df16079fcdf786",
            "b0a7e4f947db7dfb",
            "6521295dfb0a9a20",
            "ee503dc239463561",
            "42911a823405af99",
            "b9a85e50ed8bc845"
        ],
        "x": 1394,
        "y": 1599,
        "w": 832,
        "h": 562
    },
    {
        "id": "c21677dd171863d3",
        "type": "subflow",
        "name": "Subflow - Debug",
        "info": "",
        "category": "",
        "in": [
            {
                "x": 0,
                "y": 80,
                "wires": [
                    {
                        "id": "d9b0be80bc1bb9fb"
                    }
                ]
            }
        ],
        "out": [
            {
                "x": 660,
                "y": 80,
                "wires": [
                    {
                        "id": "ee11fdd3fe79df74",
                        "port": 0
                    }
                ]
            }
        ],
        "env": [],
        "meta": {},
        "color": "#DDAA99"
    },
    {
        "id": "8c3ee46cab85ef7a",
        "type": "json",
        "z": "c21677dd171863d3",
        "name": "",
        "property": "payload",
        "action": "",
        "pretty": false,
        "x": 390,
        "y": 80,
        "wires": [
            [
                "ee11fdd3fe79df74"
            ]
        ]
    },
    {
        "id": "ee11fdd3fe79df74",
        "type": "function",
        "z": "c21677dd171863d3",
        "name": "",
        "func": "// payload(json file) to msg\nfor (const [key, value] of Object.entries(msg.payload)) {\n    msg[key] = value;\n}\n\n// overwirite\nif (typeof msg.overwrite === \"object\"){\n    for (const [key, value] of Object.entries(msg.overwrite)) {\n        node.warn(`overwrite key:${key}, value:${value} ${msg[key]} => ${value}`);\n        msg[key] = value;\n    }\n}\n\n// set command\nmsg.payload = msg.command;\n\nreturn msg;",
        "outputs": 1,
        "noerr": 0,
        "initialize": "",
        "finalize": "",
        "libs": [],
        "x": 540,
        "y": 80,
        "wires": [
            []
        ]
    },
    {
        "id": "d9b0be80bc1bb9fb",
        "type": "file in",
        "z": "c21677dd171863d3",
        "name": "",
        "filename": "./data/tapoSettings.json",
        "format": "utf8",
        "chunk": false,
        "sendError": false,
        "encoding": "none",
        "allProps": false,
        "x": 190,
        "y": 80,
        "wires": [
            [
                "8c3ee46cab85ef7a"
            ]
        ]
    },
    {
        "id": "46c48181436a8401",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "command: 1",
        "props": [
            {
                "p": "command",
                "v": "1",
                "vt": "str"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 1530,
        "y": 1720,
        "wires": [
            [
                "351729dc09ee9cdc"
            ]
        ]
    },
    {
        "id": "9d37bc800fb1537f",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "active": false,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 2110,
        "y": 1720,
        "wires": []
    },
    {
        "id": "1b74c9688b25f8e7",
        "type": "tplink_toggle",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "deviceIp": "",
        "deviceAlias": "tapo alias",
        "deviceIpRange": "192.168.0.0/24",
        "searchMode": "ip",
        "x": 1910,
        "y": 2000,
        "wires": [
            [
                "c65dc6c503b12dd1"
            ]
        ]
    },
    {
        "id": "ceaf2b9baccbf204",
        "type": "tplink_status",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "deviceIp": "",
        "deviceAlias": "tapo alias",
        "deviceIpRange": "192.168.0.0/24",
        "searchMode": "ip",
        "x": 1910,
        "y": 1940,
        "wires": [
            [
                "23161dd53d6f0e38"
            ]
        ]
    },
    {
        "id": "d51d12589b13b79b",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "toggle",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 1510,
        "y": 1940,
        "wires": [
            [
                "502269dee466779f"
            ]
        ]
    },
    {
        "id": "23161dd53d6f0e38",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 2110,
        "y": 1940,
        "wires": []
    },
    {
        "id": "af53f24a391d3e82",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "toggle",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 1510,
        "y": 2000,
        "wires": [
            [
                "8877a2a4303de95a"
            ]
        ]
    },
    {
        "id": "c65dc6c503b12dd1",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 2110,
        "y": 2000,
        "wires": []
    },
    {
        "id": "83c32f2e6da79559",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "command: 0",
        "props": [
            {
                "p": "command",
                "v": "0",
                "vt": "str"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 1530,
        "y": 1680,
        "wires": [
            [
                "351729dc09ee9cdc"
            ]
        ]
    },
    {
        "id": "15983d3f7b9cb580",
        "type": "tplink_tapo_connect_api",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "deviceIp": "",
        "deviceAlias": "tapo alias",
        "deviceIpRange": "192.168.0.0/24",
        "x": 1930,
        "y": 1720,
        "wires": [
            [
                "9d37bc800fb1537f"
            ]
        ]
    },
    {
        "id": "351729dc09ee9cdc",
        "type": "subflow:c21677dd171863d3",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "x": 1730,
        "y": 1720,
        "wires": [
            [
                "15983d3f7b9cb580"
            ]
        ]
    },
    {
        "id": "502269dee466779f",
        "type": "subflow:c21677dd171863d3",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "x": 1730,
        "y": 1940,
        "wires": [
            [
                "ceaf2b9baccbf204"
            ]
        ]
    },
    {
        "id": "8877a2a4303de95a",
        "type": "subflow:c21677dd171863d3",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "env": [],
        "x": 1730,
        "y": 2000,
        "wires": [
            [
                "1b74c9688b25f8e7"
            ]
        ]
    },
    {
        "id": "efd87ba8bab74f92",
        "type": "tplink_brightness",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "deviceIp": "",
        "deviceAlias": "",
        "deviceIpRange": "",
        "searchMode": "ip",
        "x": 1930,
        "y": 1820,
        "wires": [
            [
                "b6c863060a07feb4"
            ]
        ]
    },
    {
        "id": "ba6386b9c4c4f60e",
        "type": "tplink_colour",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "deviceIp": "",
        "deviceAlias": "",
        "deviceIpRange": "",
        "colour": "#292929",
        "searchMode": "ip",
        "x": 1910,
        "y": 1880,
        "wires": [
            [
                "0e71ce5efe9543d5"
            ]
        ]
    },
    {
        "id": "6e933165ce8110ce",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "toggle",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 1510,
        "y": 1820,
        "wires": [
            [
                "b0fb1f214ac60aba"
            ]
        ]
    },
    {
        "id": "b0fb1f214ac60aba",
        "type": "subflow:c21677dd171863d3",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "x": 1730,
        "y": 1820,
        "wires": [
            [
                "efd87ba8bab74f92"
            ]
        ]
    },
    {
        "id": "342d853950376117",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "toggle",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 1510,
        "y": 1880,
        "wires": [
            [
                "73c74cf46b637ec7"
            ]
        ]
    },
    {
        "id": "73c74cf46b637ec7",
        "type": "subflow:c21677dd171863d3",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "x": 1730,
        "y": 1880,
        "wires": [
            [
                "ba6386b9c4c4f60e"
            ]
        ]
    },
    {
        "id": "0e71ce5efe9543d5",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 2110,
        "y": 1880,
        "wires": []
    },
    {
        "id": "b6c863060a07feb4",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 2110,
        "y": 1820,
        "wires": []
    },
    {
        "id": "5f3c056c6dc2b576",
        "type": "tplink_turn_off",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "deviceIp": "",
        "deviceAlias": "",
        "deviceIpRange": "",
        "searchMode": "ip",
        "x": 1920,
        "y": 2120,
        "wires": [
            [
                "ee503dc239463561"
            ]
        ]
    },
    {
        "id": "5167d005832b56c3",
        "type": "tplink_turn_on",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "deviceIp": "",
        "deviceAlias": "",
        "deviceIpRange": "",
        "searchMode": "ip",
        "x": 1920,
        "y": 2060,
        "wires": [
            [
                "6521295dfb0a9a20"
            ]
        ]
    },
    {
        "id": "2be21dc35de4d0a1",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "toggle",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 1510,
        "y": 2060,
        "wires": [
            [
                "3394762f76513829"
            ]
        ]
    },
    {
        "id": "3394762f76513829",
        "type": "subflow:c21677dd171863d3",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "env": [],
        "x": 1730,
        "y": 2060,
        "wires": [
            [
                "5167d005832b56c3"
            ]
        ]
    },
    {
        "id": "52df16079fcdf786",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "toggle",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 1510,
        "y": 2120,
        "wires": [
            [
                "b0a7e4f947db7dfb"
            ]
        ]
    },
    {
        "id": "b0a7e4f947db7dfb",
        "type": "subflow:c21677dd171863d3",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "env": [],
        "x": 1730,
        "y": 2120,
        "wires": [
            [
                "5f3c056c6dc2b576"
            ]
        ]
    },
    {
        "id": "6521295dfb0a9a20",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 2110,
        "y": 2060,
        "wires": []
    },
    {
        "id": "ee503dc239463561",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 2110,
        "y": 2120,
        "wires": []
    },
    {
        "id": "42911a823405af99",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "command: 255",
        "props": [
            {
                "p": "command",
                "v": "255",
                "vt": "str"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 1520,
        "y": 1760,
        "wires": [
            [
                "351729dc09ee9cdc"
            ]
        ]
    },
    {
        "id": "b9a85e50ed8bc845",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "069f85ce6d806e2e",
        "name": "DEBUG",
        "info": "",
        "x": 1470,
        "y": 1640,
        "wires": []
    },
    {
        "id": "31c719dd2c3a5f36",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "82788920509ba58a",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "421a846636b2b25c",
            "626c02ede6d56ec3",
            "2b6e9b2e5651defb",
            "bb6e5822918726d8"
        ],
        "x": 58,
        "y": 1593,
        "w": 1314,
        "h": 874
    },
    {
        "id": "421a846636b2b25c",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "31c719dd2c3a5f36",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "6adac2787ceb52be",
            "127b834571b481b4",
            "a1535cdf08d27f16",
            "e33543d7c10ed17b",
            "2cea3360d52f76c2",
            "6fbfb86d2dee8384",
            "141bfba31a265bb3",
            "c516288cbfb553d6",
            "a1171bc3101bb233",
            "c6477e2a8bdc2603",
            "8b3a5ace48e5ffd7",
            "ed63d43b25233835"
        ],
        "x": 94,
        "y": 2199,
        "w": 1092,
        "h": 242
    },
    {
        "id": "6adac2787ceb52be",
        "type": "tplink_tapo_connect_api",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "",
        "deviceIp": "192.168.0.100",
        "deviceAlias": "tapo alias",
        "deviceIpRange": "192.168.0.0/24",
        "x": 450,
        "y": 2300,
        "wires": [
            [
                "6fbfb86d2dee8384",
                "141bfba31a265bb3"
            ]
        ]
    },
    {
        "id": "127b834571b481b4",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "payload",
        "targetType": "msg",
        "statusVal": "",
        "statusType": "auto",
        "x": 1070,
        "y": 2280,
        "wires": []
    },
    {
        "id": "a1535cdf08d27f16",
        "type": "switch",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "TEST_NORMAL",
        "property": "payload.result",
        "propertyType": "msg",
        "rules": [
            {
                "t": "eq",
                "v": "topic.result",
                "vt": "msg"
            },
            {
                "t": "else"
            }
        ],
        "checkall": "true",
        "repair": false,
        "outputs": 2,
        "x": 700,
        "y": 2240,
        "wires": [
            [
                "e33543d7c10ed17b"
            ],
            [
                "2cea3360d52f76c2"
            ]
        ]
    },
    {
        "id": "e33543d7c10ed17b",
        "type": "change",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "OK",
        "rules": [
            {
                "t": "set",
                "p": "payload",
                "pt": "msg",
                "to": "TEST-OK",
                "tot": "str"
            }
        ],
        "action": "",
        "property": "",
        "from": "",
        "to": "",
        "reg": false,
        "x": 930,
        "y": 2280,
        "wires": [
            [
                "127b834571b481b4"
            ]
        ]
    },
    {
        "id": "2cea3360d52f76c2",
        "type": "change",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "NG",
        "rules": [
            {
                "t": "set",
                "p": "payload",
                "pt": "msg",
                "to": "TEST-NG",
                "tot": "str"
            }
        ],
        "action": "",
        "property": "",
        "from": "",
        "to": "",
        "reg": false,
        "x": 930,
        "y": 2360,
        "wires": [
            [
                "c6477e2a8bdc2603"
            ]
        ]
    },
    {
        "id": "6fbfb86d2dee8384",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "true",
        "targetType": "full",
        "statusVal": "",
        "statusType": "auto",
        "x": 450,
        "y": 2380,
        "wires": []
    },
    {
        "id": "141bfba31a265bb3",
        "type": "switch",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "",
        "property": "case",
        "propertyType": "msg",
        "rules": [
            {
                "t": "eq",
                "v": "TEST_NORMAL",
                "vt": "str"
            },
            {
                "t": "eq",
                "v": "TEST_ABNORMAL1",
                "vt": "str"
            },
            {
                "t": "eq",
                "v": "TEST_ABNORMAL2",
                "vt": "str"
            }
        ],
        "checkall": "true",
        "repair": false,
        "outputs": 3,
        "x": 630,
        "y": 2300,
        "wires": [
            [
                "a1535cdf08d27f16"
            ],
            [
                "c516288cbfb553d6"
            ],
            [
                "a1171bc3101bb233"
            ]
        ]
    },
    {
        "id": "c516288cbfb553d6",
        "type": "switch",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "TEST_ABNORMAL1",
        "property": "payload.errorInf",
        "propertyType": "msg",
        "rules": [
            {
                "t": "eq",
                "v": "topic.errorInf",
                "vt": "msg"
            },
            {
                "t": "else"
            }
        ],
        "checkall": "true",
        "repair": false,
        "outputs": 2,
        "x": 720,
        "y": 2360,
        "wires": [
            [
                "e33543d7c10ed17b"
            ],
            [
                "2cea3360d52f76c2"
            ]
        ]
    },
    {
        "id": "a1171bc3101bb233",
        "type": "switch",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "TEST_ABNORMAL2",
        "property": "payload.errorInf.message",
        "propertyType": "msg",
        "rules": [
            {
                "t": "eq",
                "v": "topic.errorInf",
                "vt": "msg"
            },
            {
                "t": "else"
            }
        ],
        "checkall": "true",
        "repair": false,
        "outputs": 2,
        "x": 720,
        "y": 2400,
        "wires": [
            [
                "e33543d7c10ed17b"
            ],
            [
                "2cea3360d52f76c2"
            ]
        ]
    },
    {
        "id": "c6477e2a8bdc2603",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "true",
        "targetType": "full",
        "statusVal": "",
        "statusType": "auto",
        "x": 1050,
        "y": 2360,
        "wires": []
    },
    {
        "id": "8b3a5ace48e5ffd7",
        "type": "link in",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "name": "",
        "links": [
            "d2e9e59038e59833",
            "f23ff3c1c6ef914e",
            "13bde9358a699fc1",
            "63f9bdd71123651a",
            "82317b5523d65203"
        ],
        "x": 135,
        "y": 2300,
        "wires": [
            [
                "ed63d43b25233835"
            ]
        ]
    },
    {
        "id": "ed63d43b25233835",
        "type": "subflow:c21677dd171863d3",
        "z": "35250d14.0fb0b2",
        "g": "421a846636b2b25c",
        "x": 270,
        "y": 2300,
        "wires": [
            [
                "6adac2787ceb52be"
            ]
        ]
    },
    {
        "id": "626c02ede6d56ec3",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "31c719dd2c3a5f36",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "8581be80eb866f03",
            "52fdf7c85fd688b6",
            "f61fd5dad9741d19"
        ],
        "x": 84,
        "y": 1619,
        "w": 728,
        "h": 548
    },
    {
        "id": "8581be80eb866f03",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "626c02ede6d56ec3",
        "name": "TEST_NORMAL",
        "info": "",
        "x": 190,
        "y": 1660,
        "wires": []
    },
    {
        "id": "52fdf7c85fd688b6",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "626c02ede6d56ec3",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "1b40e154a81920e6",
            "e7ccaabfd450127c",
            "28b78d6310c44d1e",
            "16fd767bef10c18f",
            "b7c9cfc04689f046",
            "20c74420f0f0d39e",
            "bea01c6971e80117",
            "7183ceb9e0207769",
            "2842e7c75cad1ee5",
            "d2e9e59038e59833"
        ],
        "x": 124,
        "y": 1699,
        "w": 312,
        "h": 442
    },
    {
        "id": "1b40e154a81920e6",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "command: 0",
        "props": [
            {
                "p": "command",
                "v": "0",
                "vt": "str"
            },
            {
                "p": "topic",
                "v": "{\"result\": true}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_NORMAL",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"mode\":\"command\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 260,
        "y": 1820,
        "wires": [
            [
                "d2e9e59038e59833"
            ]
        ]
    },
    {
        "id": "e7ccaabfd450127c",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "power off",
        "info": "",
        "x": 230,
        "y": 1780,
        "wires": []
    },
    {
        "id": "28b78d6310c44d1e",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "power on",
        "info": "",
        "x": 230,
        "y": 1860,
        "wires": []
    },
    {
        "id": "16fd767bef10c18f",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "command: 1",
        "props": [
            {
                "p": "command",
                "v": "1",
                "vt": "num"
            },
            {
                "p": "topic",
                "v": "{\"result\": true}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_NORMAL",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"mode\":\"command\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 260,
        "y": 1900,
        "wires": [
            [
                "d2e9e59038e59833"
            ]
        ]
    },
    {
        "id": "b7c9cfc04689f046",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "tapo device infomation",
        "info": "",
        "x": 270,
        "y": 1960,
        "wires": []
    },
    {
        "id": "20c74420f0f0d39e",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "command: 255",
        "props": [
            {
                "p": "command",
                "v": "255",
                "vt": "num"
            },
            {
                "p": "topic",
                "v": "{\"result\": true}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_NORMAL",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"mode\":\"command\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 270,
        "y": 2000,
        "wires": [
            [
                "d2e9e59038e59833"
            ]
        ]
    },
    {
        "id": "bea01c6971e80117",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "toggle",
        "props": [
            {
                "p": "topic",
                "v": "{\"result\": true}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_NORMAL",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"mode\":\"toggle\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 240,
        "y": 2100,
        "wires": [
            [
                "d2e9e59038e59833"
            ]
        ]
    },
    {
        "id": "7183ceb9e0207769",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "mode: toggle case: ip address",
        "info": "",
        "x": 270,
        "y": 2060,
        "wires": []
    },
    {
        "id": "2842e7c75cad1ee5",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "mode: command case: ip address",
        "info": "",
        "x": 280,
        "y": 1740,
        "wires": []
    },
    {
        "id": "d2e9e59038e59833",
        "type": "link out",
        "z": "35250d14.0fb0b2",
        "g": "52fdf7c85fd688b6",
        "name": "",
        "links": [
            "8b3a5ace48e5ffd7"
        ],
        "x": 385,
        "y": 2100,
        "wires": []
    },
    {
        "id": "f61fd5dad9741d19",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "626c02ede6d56ec3",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "ff32b1895420eac6",
            "47521bcab2563d4f",
            "ebf054d22b8cad87",
            "0fd11affdf163872",
            "53a0ce7eb66716e0",
            "700de514e57d8fa4",
            "f043b58a98353744",
            "d7b3283bd9c4d718",
            "11281e15de675428",
            "82317b5523d65203"
        ],
        "x": 464,
        "y": 1699,
        "w": 322,
        "h": 442
    },
    {
        "id": "ff32b1895420eac6",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "command: 0",
        "props": [
            {
                "p": "command",
                "v": "0",
                "vt": "str"
            },
            {
                "p": "topic",
                "v": "{\"result\": true}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_NORMAL",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"mode\":\"command\", \"deviceIp\": \"\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 600,
        "y": 1820,
        "wires": [
            [
                "82317b5523d65203"
            ]
        ]
    },
    {
        "id": "47521bcab2563d4f",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "power off",
        "info": "",
        "x": 570,
        "y": 1780,
        "wires": []
    },
    {
        "id": "ebf054d22b8cad87",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "power on",
        "info": "",
        "x": 570,
        "y": 1860,
        "wires": []
    },
    {
        "id": "0fd11affdf163872",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "command: 1",
        "props": [
            {
                "p": "command",
                "v": "1",
                "vt": "num"
            },
            {
                "p": "topic",
                "v": "{\"result\": true}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_NORMAL",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"mode\":\"command\", \"deviceIp\": \"\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 600,
        "y": 1900,
        "wires": [
            [
                "82317b5523d65203"
            ]
        ]
    },
    {
        "id": "53a0ce7eb66716e0",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "tapo device infomation",
        "info": "",
        "x": 610,
        "y": 1960,
        "wires": []
    },
    {
        "id": "700de514e57d8fa4",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "command: 255",
        "props": [
            {
                "p": "command",
                "v": "255",
                "vt": "num"
            },
            {
                "p": "topic",
                "v": "{\"result\": true}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_NORMAL",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"mode\":\"command\", \"deviceIp\": \"\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 610,
        "y": 2000,
        "wires": [
            [
                "82317b5523d65203"
            ]
        ]
    },
    {
        "id": "f043b58a98353744",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "toggle",
        "props": [
            {
                "p": "topic",
                "v": "{\"result\": true}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_NORMAL",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"mode\":\"toggle\", \"deviceIp\": \"\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 580,
        "y": 2100,
        "wires": [
            [
                "82317b5523d65203"
            ]
        ]
    },
    {
        "id": "d7b3283bd9c4d718",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "mode: toggle case: alias",
        "info": "",
        "x": 600,
        "y": 2060,
        "wires": []
    },
    {
        "id": "11281e15de675428",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "mode: command case: alias",
        "info": "",
        "x": 610,
        "y": 1740,
        "wires": []
    },
    {
        "id": "82317b5523d65203",
        "type": "link out",
        "z": "35250d14.0fb0b2",
        "g": "f61fd5dad9741d19",
        "name": "",
        "links": [
            "8b3a5ace48e5ffd7"
        ],
        "x": 745,
        "y": 2100,
        "wires": []
    },
    {
        "id": "2b6e9b2e5651defb",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "31c719dd2c3a5f36",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "90b1bbc2b68df25c",
            "58b8a78fecc453bb",
            "7b99c85a29fca8c6",
            "4661de6ee7f57840",
            "202173c1b476545c",
            "13bde9358a699fc1"
        ],
        "x": 824,
        "y": 1619,
        "w": 522,
        "h": 242
    },
    {
        "id": "90b1bbc2b68df25c",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "2b6e9b2e5651defb",
        "name": " Error: command not found. command: 2",
        "props": [
            {
                "p": "command",
                "v": "2",
                "vt": "str"
            },
            {
                "p": "topic",
                "v": "{\"errorInf\":\"Error: command not found.\",\"result\":false}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_ABNORMAL1",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 1080,
        "y": 1700,
        "wires": [
            [
                "13bde9358a699fc1"
            ]
        ]
    },
    {
        "id": "58b8a78fecc453bb",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "2b6e9b2e5651defb",
        "name": "Error: command not found. command: 126",
        "props": [
            {
                "p": "command",
                "v": "126",
                "vt": "str"
            },
            {
                "p": "topic",
                "v": "{\"errorInf\":\"Error: command not found.\",\"result\":false}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_ABNORMAL1",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 1090,
        "y": 1740,
        "wires": [
            [
                "13bde9358a699fc1"
            ]
        ]
    },
    {
        "id": "7b99c85a29fca8c6",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "2b6e9b2e5651defb",
        "name": "Error: command not found. command: 254",
        "props": [
            {
                "p": "command",
                "v": "254",
                "vt": "str"
            },
            {
                "p": "topic",
                "v": "{\"errorInf\":\"Error: command not found.\",\"result\":false}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_ABNORMAL1",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 1090,
        "y": 1780,
        "wires": [
            [
                "13bde9358a699fc1"
            ]
        ]
    },
    {
        "id": "4661de6ee7f57840",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "2b6e9b2e5651defb",
        "name": "Error: Invalid request or credentials",
        "props": [
            {
                "p": "command",
                "v": "1",
                "vt": "str"
            },
            {
                "p": "topic",
                "v": "{\"errorInf\":\"Error: Invalid request or credentials\",\"result\":false}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_ABNORMAL1",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"password\":\"test\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 1070,
        "y": 1820,
        "wires": [
            [
                "13bde9358a699fc1"
            ]
        ]
    },
    {
        "id": "202173c1b476545c",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "2b6e9b2e5651defb",
        "name": "TEST_ABNORMAL1",
        "info": "",
        "x": 940,
        "y": 1660,
        "wires": []
    },
    {
        "id": "13bde9358a699fc1",
        "type": "link out",
        "z": "35250d14.0fb0b2",
        "g": "2b6e9b2e5651defb",
        "name": "",
        "links": [
            "8b3a5ace48e5ffd7"
        ],
        "x": 1305,
        "y": 1820,
        "wires": []
    },
    {
        "id": "bb6e5822918726d8",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "31c719dd2c3a5f36",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "cac6ef0664fb3b88",
            "547990cb5d29505b",
            "63f9bdd71123651a"
        ],
        "x": 824,
        "y": 1879,
        "w": 522,
        "h": 122
    },
    {
        "id": "cac6ef0664fb3b88",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "bb6e5822918726d8",
        "name": "getaddrinfo ENOTFOUND 192.168.0.999",
        "props": [
            {
                "p": "command",
                "v": "1",
                "vt": "str"
            },
            {
                "p": "topic",
                "v": "{\"errorInf\":\"getaddrinfo ENOTFOUND 192.168.0.999\",\"result\":false}",
                "vt": "json"
            },
            {
                "p": "case",
                "v": "TEST_ABNORMAL2",
                "vt": "str"
            },
            {
                "p": "overwrite",
                "v": "{\"deviceIp\":\"192.168.0.999\"}",
                "vt": "json"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 1090,
        "y": 1960,
        "wires": [
            [
                "63f9bdd71123651a"
            ]
        ]
    },
    {
        "id": "547990cb5d29505b",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "bb6e5822918726d8",
        "name": "TEST_ABNORMAL2",
        "info": "",
        "x": 940,
        "y": 1920,
        "wires": []
    },
    {
        "id": "63f9bdd71123651a",
        "type": "link out",
        "z": "35250d14.0fb0b2",
        "g": "bb6e5822918726d8",
        "name": "",
        "links": [
            "8b3a5ace48e5ffd7"
        ],
        "x": 1305,
        "y": 1960,
        "wires": []
    },
    {
        "id": "b56635b3f132805e",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "2251f4edf4b86c68",
            "7b688ce95edf4463",
            "81b35f69d9d6d69d",
            "f4a4dfc5fd2ffaff",
            "0d28b02fa5bccdd6"
        ],
        "x": 714,
        "y": 379,
        "w": 632,
        "h": 202
    },
    {
        "id": "2251f4edf4b86c68",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "b56635b3f132805e",
        "name": "#cccccc",
        "props": [
            {
                "p": "payload.colour",
                "v": "#cccccc",
                "vt": "str"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 850,
        "y": 540,
        "wires": [
            [
                "0d28b02fa5bccdd6"
            ]
        ]
    },
    {
        "id": "7b688ce95edf4463",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "b56635b3f132805e",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 1230,
        "y": 480,
        "wires": []
    },
    {
        "id": "81b35f69d9d6d69d",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "b56635b3f132805e",
        "name": "white",
        "props": [
            {
                "p": "payload.colour",
                "v": "white",
                "vt": "str"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 850,
        "y": 480,
        "wires": [
            [
                "0d28b02fa5bccdd6"
            ]
        ]
    },
    {
        "id": "f4a4dfc5fd2ffaff",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "b56635b3f132805e",
        "name": "[node-colour]",
        "info": "",
        "x": 810,
        "y": 420,
        "wires": []
    },
    {
        "id": "0d28b02fa5bccdd6",
        "type": "tplink_colour",
        "z": "35250d14.0fb0b2",
        "g": "b56635b3f132805e",
        "name": "",
        "deviceIp": "192.168.0.122",
        "deviceAlias": "",
        "deviceIpRange": "",
        "colour": "#000000",
        "searchMode": "ip",
        "x": 1030,
        "y": 480,
        "wires": [
            [
                "7b688ce95edf4463"
            ]
        ]
    },
    {
        "id": "b5e3d925d80b36ad",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "99ae15c19de418c2",
            "75f168baf26da658",
            "bdc2782d2d25d384"
        ],
        "x": 34,
        "y": 1079,
        "w": 1318,
        "h": 468
    },
    {
        "id": "99ae15c19de418c2",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "b5e3d925d80b36ad",
        "name": "This \"node module: tplink_tapo_connect_api\" has been left for compatibility, this module may be deleted without notice.",
        "info": "",
        "x": 460,
        "y": 1120,
        "wires": []
    },
    {
        "id": "75f168baf26da658",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "b5e3d925d80b36ad",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "96d43c484be8f811",
            "13e9c5af0a37283e",
            "35d376d0d4289905",
            "a9fda406072de153",
            "24eba61d74a61c56"
        ],
        "x": 734,
        "y": 1159,
        "w": 592,
        "h": 182
    },
    {
        "id": "96d43c484be8f811",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "75f168baf26da658",
        "name": "toggle",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payloadType": "str",
        "x": 870,
        "y": 1300,
        "wires": [
            [
                "13e9c5af0a37283e"
            ]
        ]
    },
    {
        "id": "13e9c5af0a37283e",
        "type": "tplink_tapo_connect_api",
        "z": "35250d14.0fb0b2",
        "g": "75f168baf26da658",
        "name": "",
        "deviceIp": "192.168.0.100",
        "deviceAlias": "tapo alias",
        "deviceIpRange": "192.168.0.0/24",
        "x": 1030,
        "y": 1300,
        "wires": [
            [
                "35d376d0d4289905"
            ]
        ]
    },
    {
        "id": "35d376d0d4289905",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "75f168baf26da658",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 1210,
        "y": 1300,
        "wires": []
    },
    {
        "id": "a9fda406072de153",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "75f168baf26da658",
        "name": "toggle( \"on => off\" or \"off => on\" )",
        "info": "",
        "x": 910,
        "y": 1260,
        "wires": []
    },
    {
        "id": "24eba61d74a61c56",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "75f168baf26da658",
        "name": "[old] node-tapo-connect: toggle",
        "info": "",
        "x": 890,
        "y": 1200,
        "wires": []
    },
    {
        "id": "bdc2782d2d25d384",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "g": "b5e3d925d80b36ad",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "fb493813.249f08",
            "8311f395.25e56",
            "2aa38c09.564724",
            "9158e6ef.dd5d78",
            "79f7a84a.4c4d88",
            "27568da0.cc1852",
            "3338a0f2585b9662",
            "f5ca83ef74c5c137",
            "b25960c8c58ef24c",
            "61a4a5ca77c19e36"
        ],
        "x": 74,
        "y": 1159,
        "w": 632,
        "h": 362
    },
    {
        "id": "fb493813.249f08",
        "type": "tplink_tapo_connect_api",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "",
        "deviceIp": "",
        "deviceAlias": "tapo alias",
        "deviceIpRange": "192.168.0.0/24",
        "mode": "command",
        "x": 410,
        "y": 1300,
        "wires": [
            [
                "2aa38c09.564724"
            ]
        ]
    },
    {
        "id": "8311f395.25e56",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payload": "1",
        "payloadType": "num",
        "x": 210,
        "y": 1380,
        "wires": [
            [
                "fb493813.249f08"
            ]
        ]
    },
    {
        "id": "2aa38c09.564724",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 590,
        "y": 1300,
        "wires": []
    },
    {
        "id": "9158e6ef.dd5d78",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payload": "0",
        "payloadType": "str",
        "x": 210,
        "y": 1300,
        "wires": [
            [
                "fb493813.249f08"
            ]
        ]
    },
    {
        "id": "79f7a84a.4c4d88",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "tapo device infomation",
        "info": "",
        "x": 220,
        "y": 1440,
        "wires": []
    },
    {
        "id": "27568da0.cc1852",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "power off",
        "info": "",
        "x": 180,
        "y": 1260,
        "wires": []
    },
    {
        "id": "3338a0f2585b9662",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "",
        "props": [
            {
                "p": "payload"
            },
            {
                "p": "topic",
                "vt": "str"
            }
        ],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "payload": "255",
        "payloadType": "num",
        "x": 210,
        "y": 1480,
        "wires": [
            [
                "fb493813.249f08"
            ]
        ]
    },
    {
        "id": "f5ca83ef74c5c137",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "power on",
        "info": "",
        "x": 180,
        "y": 1340,
        "wires": []
    },
    {
        "id": "b25960c8c58ef24c",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "[old]tapo connect module: toggle",
        "info": "",
        "x": 490,
        "y": 1260,
        "wires": []
    },
    {
        "id": "61a4a5ca77c19e36",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "bdc2782d2d25d384",
        "name": "[old] node-tapo-connect: command",
        "info": "",
        "x": 240,
        "y": 1200,
        "wires": []
    },
    {
        "id": "d9911e3830e586ee",
        "type": "group",
        "z": "35250d14.0fb0b2",
        "style": {
            "stroke": "#999999",
            "stroke-opacity": "1",
            "fill": "none",
            "fill-opacity": "1",
            "label": true,
            "label-position": "nw",
            "color": "#a4a4a4"
        },
        "nodes": [
            "dff10f578aa5b66c",
            "a78a0795cccf664d",
            "ab92ef78b8813a7a",
            "2aa4613a0d8d09a9"
        ],
        "x": 714,
        "y": 19,
        "w": 632,
        "h": 142
    },
    {
        "id": "dff10f578aa5b66c",
        "type": "debug",
        "z": "35250d14.0fb0b2",
        "g": "d9911e3830e586ee",
        "name": "",
        "active": true,
        "tosidebar": true,
        "console": false,
        "tostatus": false,
        "complete": "false",
        "statusVal": "",
        "statusType": "auto",
        "x": 1230,
        "y": 120,
        "wires": []
    },
    {
        "id": "a78a0795cccf664d",
        "type": "inject",
        "z": "35250d14.0fb0b2",
        "g": "d9911e3830e586ee",
        "name": "",
        "props": [],
        "repeat": "",
        "crontab": "",
        "once": false,
        "onceDelay": 0.1,
        "topic": "",
        "x": 850,
        "y": 120,
        "wires": [
            [
                "2aa4613a0d8d09a9"
            ]
        ]
    },
    {
        "id": "ab92ef78b8813a7a",
        "type": "comment",
        "z": "35250d14.0fb0b2",
        "g": "d9911e3830e586ee",
        "name": "[node-turn-on]",
        "info": "",
        "x": 810,
        "y": 60,
        "wires": []
    },
    {
        "id": "2aa4613a0d8d09a9",
        "type": "tplink_turn_on",
        "z": "35250d14.0fb0b2",
        "g": "d9911e3830e586ee",
        "name": "",
        "deviceIp": "192.168.0.122",
        "deviceAlias": "",
        "deviceIpRange": "",
        "searchMode": "ip",
        "x": 1040,
        "y": 120,
        "wires": [
            [
                "dff10f578aa5b66c"
            ]
        ]
    }
]
```
