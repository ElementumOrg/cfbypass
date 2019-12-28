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

Or with HttpClient:

    httpClient = &http.Client{}

	buffer := new(bytes.Buffer)
	req, err := http.NewRequest("GET", "https://test.com/", buffer)
	if err != nil {
		return err
	}

	// Set custom headers
	req.Header.Add("User-Agent", `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.27 Safari/537.36`)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if IsCloudFlared(resp) {
		if resp, err = RunClient(resp, httpClient); err != nil {
            return err
	    }
	}

    // Here you should already have response, 
    // after solving CloudFlare and re-requesting from destination website.
