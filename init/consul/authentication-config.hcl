watches = [
  {
    type = "keyprefix"
    prefix = "authentication/"
    handler_type = "http"
    http_handler_config {
      path = "http://host.docker.internal:8081/watch"
      method = "POST"
      timeout = "10s"
      tls_skip_verify = false
    }
  }
]