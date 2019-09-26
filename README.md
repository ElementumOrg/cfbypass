Small library for bypassing CloudFlare challenges.

Give it a proxy request result, it will check if passing of challenge is needed, pass it and re-submit the request with included CloudFlare cookies.

Example of usage:

	Proxy = goproxy.NewProxyHttpServer()
	Proxy.OnResponse().DoFunc(handleResponse)

    ... 

    func handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
        defer ctx.Req.Body.Close()

        if resp == nil {
            return resp
        }

        if cfResp, err := cfbypass.RunProxy(resp, ctx); err != nil {
            log.Warningf("Could not solve the CloudFlare challenge: ", err)
        } else if cfResp != nil {
            return cfResp
        }

        return resp
    }
