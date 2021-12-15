return {
    no_consumer = true, -- This means our plugin will not apply to specific service consumers
    fields = {
        enabled = {
            type     = "boolean",
            required = true,
            default  = true
        }
    }
}