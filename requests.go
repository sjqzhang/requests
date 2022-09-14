/* Copyright（2） 2018 by  asmcos .
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package requests

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

var VERSION string = "0.8"

var DEBUG bool = false
var logger io.Writer

type Request struct {
	httpreq *http.Request
	Header  *http.Header
	Client  *http.Client
	Debug   bool
	Cookies []*http.Cookie
	Logger  io.Writer
}

type Response struct {
	R       *http.Response
	content []byte
	text    string
	req     *Request
}

//type ContentType int
//
//const (
//	ContentTypeFormEncoded ContentType = 0
//	ContentTypeJsonEncoded ContentType = 1
//)

type Header map[string]string
type Params map[string]string
type Datas map[string]string // for post form
type Files map[string]string // name ,filename

// {username,password}
type Auth []string

func Requests() *Request {

	req := new(Request)

	req.httpreq = &http.Request{
		Method:     "GET",
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req.Header = &req.httpreq.Header
	req.httpreq.Header.Set("User-Agent", "Go-Requests "+VERSION)

	req.Client = &http.Client{}
	if logger == nil {
		req.Logger = new(bytes.Buffer)
	} else {
		req.Logger = logger
	}

	// auto with Cookies
	// cookiejar.New source code return jar, nil
	jar, _ := cookiejar.New(nil)

	req.Client.Jar = jar

	if DEBUG {
		req.Debug = DEBUG
	}
	return req
}

func SetLogger(log io.Writer) {
	logger = log
}

func NewRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

func NewRequestForTest(method, origurl string, args ...interface{}) (*http.Request, error) {
	req := Requests()
	req.httpreq.Method = method
	//set default
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// set params ?a=b&b=c
	//set Header
	var params []map[string]string
	var datas []map[string]string // POST
	var files []map[string]string //post file

	//reset Cookies,
	//Client.Do can copy cookie from client.Jar to req.Header
	delete(req.httpreq.Header, "Cookie")

	for _, arg := range args {
		switch a := arg.(type) {
		// arg is Header , set to request header
		case Header:

			for k, v := range a {
				req.Header.Set(k, v)
			}
			// arg is "GET" params
			// ?title=website&id=1860&from=login
		case Params:
			params = append(params, a)

		case Datas: //Post form data,packaged in body.
			datas = append(datas, a)
		case Files:
			files = append(files, a)
		case Auth:
			// a{username,password}
			req.httpreq.SetBasicAuth(a[0], a[1])
		}
	}

	disturl, _ := buildURLParams(origurl, params...)

	if len(files) > 0 {
		req.buildFilesAndForms(files, datas)

	} else {
		Forms := req.buildForms(datas...)
		req.setBodyBytes(Forms) // set forms to body
	}
	URL, err := url.Parse(disturl)
	if err != nil {
		return nil, err
	}
	req.httpreq.URL = URL
	return req.httpreq, nil
}

// Get ,req.Get

func Get(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.Get(origurl, args...)
	return resp, err
}

func (req *Request) Get(origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = "GET"

	// set params ?a=b&b=c
	//set Header
	var params []map[string]string

	//reset Cookies,
	//Client.Do can copy cookie from client.Jar to req.Header
	delete(req.httpreq.Header, "Cookie")

	for _, arg := range args {
		switch a := arg.(type) {
		// arg is Header , set to request header
		case Header:

			for k, v := range a {
				req.Header.Set(k, v)
			}
			// arg is "GET" params
			// ?title=website&id=1860&from=login
		case Params:
			params = append(params, a)
		case Auth:
			// a{username,password}
			req.httpreq.SetBasicAuth(a[0], a[1])
		}
	}

	disturl, _ := buildURLParams(origurl, params...)

	//prepare to Do
	URL, err := url.Parse(disturl)
	if err != nil {
		return nil, err
	}
	req.httpreq.URL = URL

	req.ClientSetCookies()

	req.RequestDebug()

	res, err := req.Client.Do(req.httpreq)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	resp = &Response{}
	resp.R = res
	resp.req = req

	resp.Content()
	defer res.Body.Close()

	resp.ResponseDebug()
	return resp, nil
}

// handle URL params
func buildURLParams(userURL string, params ...map[string]string) (string, error) {
	parsedURL, err := url.Parse(userURL)

	if err != nil {
		return "", err
	}

	parsedQuery, err := url.ParseQuery(parsedURL.RawQuery)

	if err != nil {
		return "", nil
	}

	for _, param := range params {
		for key, value := range param {
			parsedQuery.Add(key, value)
		}
	}
	return addQueryParams(parsedURL, parsedQuery), nil
}

func addQueryParams(parsedURL *url.URL, parsedQuery url.Values) string {
	if len(parsedQuery) > 0 {
		return strings.Join([]string{strings.Replace(parsedURL.String(), "?"+parsedURL.RawQuery, "", -1), parsedQuery.Encode()}, "?")
	}
	return strings.Replace(parsedURL.String(), "?"+parsedURL.RawQuery, "", -1)
}

func (req *Request) RequestDebug() {

	buf := new(bytes.Buffer)
	buf.WriteString("-------------------Begin---------------------\n")
	buf.WriteString(fmt.Sprintf("Method:%v\n", req.httpreq.Method))
	buf.WriteString(fmt.Sprintf("URL:%v\n", req.httpreq.URL))
	buf.WriteString(fmt.Sprintf("Header:%v\n", req.httpreq.Header))
	if v, ok := req.httpreq.Header["Content-Type"]; ok {
		if strings.Contains(strings.ToLower(v[0]), "multipart/form-data") {
			//buf.WriteString(fmt.Sprintf("Body:%v\n", req.httpreq.MultipartForm))
		} else {
			if req.httpreq.Body != nil {
				var body bytes.Buffer
				_, err := io.Copy(&body, req.httpreq.Body)
				if err != nil {
					fmt.Println(err)
				}
				req.httpreq.Body = ioutil.NopCloser(bytes.NewBuffer(body.Bytes()))
				buf.WriteString(fmt.Sprintf("Body:%v\n", body.String()))
			}
		}
	}
	if req.Logger != nil {
		buf.WriteTo(req.Logger)
	}
	if !req.Debug {
		return
	}

	fmt.Println("===========Go RequestDebug ============")

	message, err := httputil.DumpRequestOut(req.httpreq, false)
	if err != nil {
		return
	}
	fmt.Println(string(message))

	if len(req.Client.Jar.Cookies(req.httpreq.URL)) > 0 {
		fmt.Println("Cookies:")
		for _, cookie := range req.Client.Jar.Cookies(req.httpreq.URL) {
			fmt.Println(cookie)
		}
	}
}

// cookies
// cookies only save to Client.Jar
// req.Cookies is temporary
func (req *Request) SetCookie(cookie *http.Cookie) {
	req.Cookies = append(req.Cookies, cookie)
}

func (req *Request) ClearCookies() {
	req.Cookies = req.Cookies[0:0]
}

func (req *Request) ClientSetCookies() {

	if len(req.Cookies) > 0 {
		// 1. Cookies have content, Copy Cookies to Client.jar
		// 2. Clear  Cookies
		req.Client.Jar.SetCookies(req.httpreq.URL, req.Cookies)
		req.ClearCookies()
	}

}

// set timeout s = second
func (req *Request) SetTimeout(n time.Duration) {
	req.Client.Timeout = time.Duration(n * time.Second)
}

func (req *Request) Close() {
	req.httpreq.Close = true
}

func (req *Request) Proxy(proxyurl string) {

	urli := url.URL{}
	urlproxy, err := urli.Parse(proxyurl)
	if err != nil {
		fmt.Println("Set proxy failed")
		return
	}
	req.Client.Transport = &http.Transport{
		Proxy:           http.ProxyURL(urlproxy),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

}

/**************/
func (resp *Response) ResponseDebug() {
	buf := new(bytes.Buffer)
	buf.WriteString(fmt.Sprintf("Status:%v\n", resp.R.Status))
	buf.WriteString(fmt.Sprintf("StatusCode:%v\n", resp.R.StatusCode))
	buf.WriteString(fmt.Sprintf("Header:%v\n", resp.R.Header))
	buf.WriteString("-------------------End---------------------\n")
	buf.WriteTo(resp.req.Logger)

	if !resp.req.Debug {
		return
	}

	fmt.Println("===========Go ResponseDebug ============")

	message, err := httputil.DumpResponse(resp.R, false)
	if err != nil {
		return
	}

	fmt.Println(string(message))

}

func (resp *Response) Content() []byte {

	var err error

	if len(resp.content) > 0 {
		return resp.content
	}

	var Body = resp.R.Body
	if resp.R.Header.Get("Content-Encoding") == "gzip" && resp.req.Header.Get("Accept-Encoding") != "" {
		// fmt.Println("gzip")
		reader, err := gzip.NewReader(Body)
		if err != nil {
			return nil
		}
		Body = reader
	}

	resp.content, err = ioutil.ReadAll(Body)
	if err != nil {
		return nil
	}

	return resp.content
}

func (resp *Response) Text() string {
	if resp.content == nil {
		resp.Content()
	}
	resp.text = string(resp.content)
	return resp.text
}

func (resp *Response) SaveFile(filename string) error {
	if resp.content == nil {
		resp.Content()
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(resp.content)
	f.Sync()

	return err
}

func (resp *Response) Json(v interface{}) error {
	if resp.content == nil {
		resp.Content()
	}
	return json.Unmarshal(resp.content, v)
}

func (resp *Response) JsonPretty() (string, error) {
	var obj interface{}
	if resp.content == nil {
		resp.Content()
	}
	err := json.Unmarshal(resp.content, &obj)
	if err != nil {
		return "", err
	} else {
		bs, err := json.MarshalIndent(&obj, "", " ")
		if err != nil {
			return "", err
		}
		return string(bs), nil
	}
}

func (resp *Response) PrintToConsole() {
	body := string(resp.content)
	body = strings.TrimSpace(body)
	if strings.HasPrefix(body, "{") && strings.HasSuffix(body, "}") {
		body, err := resp.JsonPretty()
		if err != nil {
			fmt.Println(body)
		} else {
			fmt.Println(body)
		}
	} else {
		fmt.Println(string(resp.content))
	}
}

func (resp *Response) JsonToMap() (map[string]interface{}, error) {
	if resp.content == nil {
		resp.Content()
	}
	var data map[string]interface{}
	return data, json.Unmarshal(resp.content, &data)
}

func (resp *Response) Cookies() (cookies []*http.Cookie) {
	httpreq := resp.req.httpreq
	client := resp.req.Client

	cookies = client.Jar.Cookies(httpreq.URL)

	return cookies

}

/**************post*************************/
// call req.Post ,only for easy
func Post(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.Post(origurl, args...)
	return resp, err
}

func PostJson(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.PostJson(origurl, args...)
	return resp, err
}

// POST requests

func (req *Request) PostJson(origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = "POST"

	req.Header.Set("Content-Type", "application/json")

	//reset Cookies,
	//Client.Do can copy cookie from client.Jar to req.Header
	delete(req.httpreq.Header, "Cookie")

	for _, arg := range args {
		switch a := arg.(type) {
		// arg is Header , set to request header
		case Header:

			for k, v := range a {
				req.Header.Set(k, v)
			}
		case string:
			req.setBodyRawBytes(ioutil.NopCloser(strings.NewReader(arg.(string))))
		case Auth:
			// a{username,password}
			req.httpreq.SetBasicAuth(a[0], a[1])
		default:
			b := new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(a)
			if err != nil {
				return nil, err
			}
			req.setBodyRawBytes(ioutil.NopCloser(b))
		}
	}

	//prepare to Do
	URL, err := url.Parse(origurl)
	if err != nil {
		return nil, err
	}
	req.httpreq.URL = URL

	req.ClientSetCookies()

	req.RequestDebug()

	res, err := req.Client.Do(req.httpreq)

	// clear post  request information
	req.httpreq.Body = nil
	req.httpreq.GetBody = nil
	req.httpreq.ContentLength = 0

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	resp = &Response{}
	resp.R = res
	resp.req = req

	resp.Content()
	defer res.Body.Close()
	resp.ResponseDebug()
	return resp, nil
}

/*
	MethodGet     = "GET"
	MethodHead    = "HEAD"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodPatch   = "PATCH" // RFC 5789
	MethodDelete  = "DELETE"
	MethodConnect = "CONNECT"
	MethodOptions = "OPTIONS"
	MethodTrace   = "TRACE"
*/

func Head(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	return req.Do(http.MethodHead, origurl, args...)
}
func Put(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	return req.Do(http.MethodPut, origurl, args...)
}
func PutJson(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	req.Header.Set("Content-Type", "application/json")
	return req.Do(http.MethodPut, origurl, args...)
}
func Trace(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	return req.Do(http.MethodTrace, origurl, args...)
}
func Delete(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	return req.Do(http.MethodDelete, origurl, args...)
}
func Options(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	return req.Do(http.MethodOptions, origurl, args...)
}
func Patch(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()
	return req.Do(http.MethodPatch, origurl, args...)
}

func (req *Request) Head(origurl string, args ...interface{}) (resp *Response, err error) {
	return req.Do(http.MethodHead, origurl, args...)
}
func (req *Request) Put(origurl string, args ...interface{}) (resp *Response, err error) {
	return req.Do(http.MethodPut, origurl, args...)
}
func (req *Request) PutJson(origurl string, args ...interface{}) (resp *Response, err error) {
	req.Header.Set("Content-Type", "application/json")
	return req.Do(http.MethodPut, origurl, args...)
}
func (req *Request) Trace(origurl string, args ...interface{}) (resp *Response, err error) {
	return req.Do(http.MethodTrace, origurl, args...)
}
func (req *Request) Delete(origurl string, args ...interface{}) (resp *Response, err error) {
	return req.Do(http.MethodDelete, origurl, args...)
}
func (req *Request) Options(origurl string, args ...interface{}) (resp *Response, err error) {
	return req.Do(http.MethodOptions, origurl, args...)
}
func (req *Request) Patch(origurl string, args ...interface{}) (resp *Response, err error) {
	return req.Do(http.MethodPatch, origurl, args...)
}

func (req *Request) Do(method string, origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = method

	//set default
	//req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// set params ?a=b&b=c
	//set Header
	params := []map[string]string{}
	datas := []map[string]string{} // POST
	files := []map[string]string{} //post file

	//reset Cookies,
	//Client.Do can copy cookie from client.Jar to req.Header
	delete(req.httpreq.Header, "Cookie")

	for _, arg := range args {
		switch a := arg.(type) {
		// arg is Header , set to request header
		case Header:

			for k, v := range a {
				req.Header.Set(k, v)
			}
			// arg is "GET" params
			// ?title=website&id=1860&from=login
		case Params:
			params = append(params, a)
		case string:
			req.setBodyRawBytes(ioutil.NopCloser(strings.NewReader(arg.(string))))
		case Datas: //Post form data,packaged in body.
			datas = append(datas, a)
		case Files:
			files = append(files, a)
		case Auth:
			// a{username,password}
			req.httpreq.SetBasicAuth(a[0], a[1])
		default:
			b := new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(a)
			if err != nil {
				return nil, err
			}
			req.setBodyRawBytes(ioutil.NopCloser(b))
		}
	}

	disturl, _ := buildURLParams(origurl, params...)

	if len(files) > 0 {
		req.buildFilesAndForms(files, datas)

	} else {
		if len(datas) > 0 {
			Forms := req.buildForms(datas...)
			req.setBodyBytes(Forms) // set forms to body
		}
	}
	//prepare to Do
	URL, err := url.Parse(disturl)
	if err != nil {
		return nil, err
	}
	req.httpreq.URL = URL

	req.ClientSetCookies()

	req.RequestDebug()

	res, err := req.Client.Do(req.httpreq)

	// clear post param
	req.httpreq.Body = nil
	req.httpreq.GetBody = nil
	req.httpreq.ContentLength = 0

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	resp = &Response{}
	resp.R = res
	resp.req = req

	resp.Content()
	defer res.Body.Close()

	resp.ResponseDebug()
	return resp, nil
}

func (req *Request) Post(origurl string, args ...interface{}) (resp *Response, err error) {

	req.httpreq.Method = "POST"

	//set default
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// set params ?a=b&b=c
	//set Header
	var params []map[string]string
	var datas []map[string]string // POST
	var files []map[string]string //post file

	//reset Cookies,
	//Client.Do can copy cookie from client.Jar to req.Header
	delete(req.httpreq.Header, "Cookie")

	for _, arg := range args {
		switch a := arg.(type) {
		// arg is Header , set to request header
		case Header:

			for k, v := range a {
				req.Header.Set(k, v)
			}
			// arg is "GET" params
			// ?title=website&id=1860&from=login
		case Params:
			params = append(params, a)

		case Datas: //Post form data,packaged in body.
			datas = append(datas, a)
		case Files:
			files = append(files, a)
		case Auth:
			// a{username,password}
			req.httpreq.SetBasicAuth(a[0], a[1])
		}
	}

	disturl, _ := buildURLParams(origurl, params...)

	if len(files) > 0 {
		req.buildFilesAndForms(files, datas)

	} else {
		Forms := req.buildForms(datas...)
		req.setBodyBytes(Forms) // set forms to body
	}
	//prepare to Do
	URL, err := url.Parse(disturl)
	if err != nil {
		return nil, err
	}
	req.httpreq.URL = URL

	req.ClientSetCookies()

	req.RequestDebug()

	res, err := req.Client.Do(req.httpreq)

	// clear post param
	req.httpreq.Body = nil
	req.httpreq.GetBody = nil
	req.httpreq.ContentLength = 0

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	resp = &Response{}
	resp.R = res
	resp.req = req

	resp.Content()
	defer res.Body.Close()

	resp.ResponseDebug()
	return resp, nil
}

// only set forms
func (req *Request) setBodyBytes(Forms url.Values) {

	// maybe
	data := Forms.Encode()
	req.httpreq.Body = ioutil.NopCloser(strings.NewReader(data))
	req.httpreq.ContentLength = int64(len(data))
}

// only set forms
func (req *Request) setBodyRawBytes(read io.ReadCloser) {
	req.httpreq.Body = read
}

// upload file and form
// build to body format
func (req *Request) buildFilesAndForms(files []map[string]string, datas []map[string]string) {

	//handle file multipart

	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	for _, file := range files {
		for k, v := range file {
			part, err := w.CreateFormFile(k, v)
			if err != nil {
				fmt.Printf("Upload %s failed!", v)
				panic(err)
			}
			file := openFile(v)
			_, err = io.Copy(part, file)
			if err != nil {
				panic(err)
			}
		}
	}

	for _, data := range datas {
		for k, v := range data {
			w.WriteField(k, v)
		}
	}

	w.Close()
	// set file header example:
	// "Content-Type": "multipart/form-data; boundary=------------------------7d87eceb5520850c",
	req.httpreq.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
	req.httpreq.ContentLength = int64(b.Len())
	req.Header.Set("Content-Type", w.FormDataContentType())
}

// build post Form data
func (req *Request) buildForms(datas ...map[string]string) (Forms url.Values) {
	Forms = url.Values{}
	for _, data := range datas {
		for key, value := range data {
			Forms.Add(key, value)
		}
	}
	return Forms
}

// open file for post upload files

func openFile(filename string) *os.File {
	r, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	return r
}
