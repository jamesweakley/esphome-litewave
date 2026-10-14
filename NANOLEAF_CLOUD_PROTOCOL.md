## Capturing device information from Nanoleaf cloud

Login with username and password:

```
curl 'https://my.nanoleaf.me/api/v1/users/local/login' \
    -X POST \
    -H 'Authorization: Bearer' \
    -H 'Content-Type: application/json' \
    --data-raw '{"grant_type":"password","username":"<email>","password": "<password>"}'
```

Response:

```
{
  "access_token": "eyJhbG....ZXlwgKHx4",
  "refresh_token": "eyJhbG....vXn03F_Hjbukc_I",
  "id": "678b2cb7...07870",
  "token_type": "Bearer",
  "expires_in": 604800,
  "user_profile": {
    "first_name": "John",
    "last_name": "Smith",
    "display_name": "My Home"
  },
  "cloud_version": 4
}
```

Then query home information:

```
curl 'https://my.nanoleaf.me/api/v2/homesync' \
-X GET \
-H 'Authorization: Bearer eyJhbG....ZXlwgKHx4' \
-H 'Accept: application/json, text/plain, */*' \
-H 'Accept-Language: en-GB' \
-H 'Content-Type: application/json' 
```

Response:

```
{
    "updated": {
        "api": "v2"
    },
    "isUsingThread": {
        "ios": true
    },
    "_id": "678b...2a84",
    "homes": [
        {
            "individual_updated_at": {
                "name": 1791857234,
                "deleted": 1791857234
            },
            "name": "My Home",
            "cloudID": "678b2c....85",
            "primary": false,
            "zones": [],
            "triggers": [],
            "preferredChannel": 26,
            "sharedSecret": "076ff96b2...b79bc",
            "panID": "aaaa",
            "adminKey": "bbbb",
            "deleted": false,
            "updated_at": 1791944172
        }
    ],
    "rooms": [
        {
            "individual_updated_at": {
                "name": 1762939579,
                "deleted": 1762939579
            },
            "cloudID": "678b...2a84",
            "name": "Upstairs Study",
            "homeID": "678b....2a85",
            "isDefault": false,
            "deleted": false,
            "updated_at": 1791944174
        }
    ],
    "devices": [
        {
            "individual_updated_at": {
                "name": 1762130203,
                "deleted": 1762130203,
                "roomID": 1762130203,
                "essentials_scenes": 1762130203
            },
            "deviceID": "U24460V0003:1",
            "cloudID": "68a12d36be6c5103b813b155",
            "name": "U Br4 DL1",
            "aid": 1,
            "homeID": "678b....2a85",
            "roomID": "678b...2a84",
            "services": [],
            "deleted": false,
            "updated_at": 1791944177,
            "essentials_scenes": {
                "251": "Northern Lights",
                "252": "Blaze"
            },
            "model": "NL65",
            "hardware_version": "1.2.0",
            "software_version": "5.1.45",
            "auth_token": "c16a...f67",
            "pairing_id": "68e0",
            "EUI": "0c2a6ffffeac2ad2"
        },
        {
            "individual_updated_at": {
                "name": 1762130203,
                "deleted": 1762130203,
                "roomID": 1762130203,
                "essentials_scenes": 1762130203
            },
            "deviceID": "U24460V0K89:1",
            "cloudID": "68a27571ca25b003d20e9a26",
            "name": "U Br4 DL2",
            "aid": 1,
            "homeID": "678b....2a85",
            "roomID": "678b...2a84",
            "services": [],
            "deleted": false,
            "updated_at": 1791944177,
            "essentials_scenes": {
                "251": "Northern Lights",
                "252": "Blaze",
                "253": "Date Night",
                "254": "Starlight"
            },
            "model": "NL65",
            "hardware_version": "1.2.0",
            "software_version": "5.1.45",
            "auth_token": "fbeb9a6...7749",
            "pairing_id": "76c8",
            "EUI": "0c2a6ffffeb858f8"
        },
        {
            "deviceID": "S25170U1533:1",
            "cloudID": "6acca6a83272d397c47df1ee",
            "name": "Upstairs Study Wireless Switch 1",
            "aid": 1,
            "homeID": "678b....2a85",
            "roomID": "678b...2a84",
            "services": [],
            "deleted": false,
            "updated_at": 1791944177,
            "model": "NL44",
            "hardware_version": "1.0.7",
            "software_version": "4.1.14",
            "auth_token": "71a8489...929f",
            "pairing_id": "a600",
            "EUI": "e406bffffed47797"
        }
    ],
    "actionSets": [],
    "playlists": [],
    "threadNetworks": [],
    "sensePlusGroups": [
        {
            "actions": {
                "left": {
                    "single": {
                        "action": 2
                    },
                    "double": {
                        "action": 2
                    },
                    "long": {
                        "action": -1
                    }
                },
                "right": {
                    "single": {
                        "action": 1
                    },
                    "double": {
                        "action": 1
                    },
                    "long": {
                        "action": -1
                    }
                }
            },
            "individual_updated_at": {
                "name": 1791866025,
                "devices": 1791866100,
                "motionTimeout": 1791866025,
                "dynamicTimeout": 1791866025,
                "daylightSensitivity": 1791866025,
                "daylightEnabled": 1791866025,
                "nightEnabled": 1791866025,
                "nightStart": 1791866025,
                "nightEnd": 1791866025,
                "actions": 1791866025,
                "deleted": 1791866025
            },
            "name": "Test Group",
            "devices": [],
            "motionTimeout": 1200,
            "dynamicTimeout": false,
            "daylightSensitivity": 30,
            "daylightEnabled": false,
            "homeID": "678b....2a85",
            "nightEnabled": false,
            "nightStart": 28800,
            "nightEnd": 79200,
            "uuid": "b20fd459-5a64-4df4-af6e-fcf3378be53a",
            "fadeoutTimeout": 180,
            "roomMotionEnabled": true,
            "channel": 26,
            "deleted": false,
            "updated_at": 1791866100
        }
    ],
    "user_id": "678b2cb785d26f5dc0107870",
    "updated_at": "2026-10-14T02:16:19.500Z",
    "__v": 5,
    "updated_at_epoch": 1791866853
}
```