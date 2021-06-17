# Goal
To run data retention based on custom criteria:
- Keep scans going back X days
- Keep latest Y scans
- Keep earliest Z scans

*By default, the script runs in dry run  mode – and does not run DR. This is a fail-safe to prevent accidentally deleting data.*

**To actually run DR, they have to explicitly provide the -exec parameter.**

# JSON Config
Update the relevant sections of the JSON config file:

```
{
    "log": {
        "timeFormat" : "R"
    },
    "cx": {
        "host" : "http://UPDATE_ME",
        "username" : "UPDATE_ME",
        "password" : "UPDATE_ME",
        "db": {
            "instance": "SQLSERVER_INSTANCE\\UPDATE_ME",
            "username": "",
            "password": ""
        }
    },
    "dataRetention": {
        "daysToRetain" : 145,
        "latestScansToRetain" : 0,
        "earliestScansToRetain" : 0,
        "removeScansWithNoCodeChange" : false,
        "durationLimitHours" : 4
    }
}
```
