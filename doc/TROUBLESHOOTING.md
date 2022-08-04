# Troubleshooting

You may be experiencing one of these issues:

### QuestDB configuration

If you can't initially see your data through a `select` query straight away,
this is normal: by default the database will only commit data it receives
though the line protocol periodically to maximize throughput.

For dev/testing you may want to tune the following database configuration
parameters as so:

```ini
# server.conf
cairo.max.uncommitted.rows=1
line.tcp.maintenance.job.interval=100
```

The defaults are more applicable for a production environment.

For these and more configuration parameters refer to [database configuration
](https://questdb.io/docs/reference/configuration/)documentation.

### API usage
The API doesn't send any data over the network until the `line_sender_flush`
function (if using the C API) or `.flush()` method (if using the C++ API API)
is called.

*Closing the connection will not auto-flush.*
