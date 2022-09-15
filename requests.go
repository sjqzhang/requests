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
	"context"
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

var Debug bool = false
var logger io.Writer

type Settings struct {
	Debug     bool
	Callbacks []Callback
}

type Callback func(ctx context.Context, req *http.Request, resp *http.Response, err error)

var settings = Settings{
	Debug:     false,
	Callbacks: []Callback{},
}

type Request struct {
	HttpRequest *http.Request
	Header      *http.Header
	Client      *http.Client
	Debug       bool
	Cookies     []*http.Cookie
	Logger      io.Writer
	Settings    Settings
	Callbacks   []Callback
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

	req.HttpRequest = &http.Request{
		Method:     "GET",
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	req.Settings = settings
	req.Header = &req.HttpRequest.Header
	req.HttpRequest.Header.Set("User-Agent", "Go-Requests "+VERSION)

	req.Client = &http.Client{}
	if logger == nil {
		if Debug {
			req.Logger = os.Stdout
		} else {
			req.Logger = new(bytes.Buffer)
		}
	} else {
		req.Logger = logger
	}

	// auto with Cookies
	// cookiejar.New source code return jar, nil
	jar, _ := cookiejar.New(nil)

	req.Client.Jar = jar

	if len(settings.Callbacks) > 0 {
		req.Callbacks = settings.Callbacks
	}

	if Debug {
		req.Debug = Debug
	}
	return req
}

func SetLogger(log io.Writer) {
	logger = log
}

func RegisterCallback(callbacks ...Callback) {
	settings.Callbacks = append(settings.Callbacks, callbacks...)
}

func NewRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

func NewRequestForTest(method, origurl string, args ...interface{}) (*http.Request, error) {
	req := Requests()
	req.HttpRequest.Method = method
	//set default
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// set params ?a=b&b=c
	//set Header
	var params []map[string]string
	var datas []map[string]string // POST
	var files []map[string]string //post file

	//reset Cookies,
	//Client.Do can copy cookie from client.Jar to req.Header
	delete(req.HttpRequest.Header, "Cookie")

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
			req.HttpRequest.SetBasicAuth(a[0], a[1])
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
	req.HttpRequest.URL = URL
	return req.HttpRequest, nil
}

// Get ,req.Get

func Get(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request Get
	resp, err = req.Get(origurl, args...)
	return resp, err
}
func (req *Request) WithContext(ctx context.Context) *Request {
	req.HttpRequest = req.HttpRequest.WithContext(ctx)
	return req
}

func (req *Request) Get(origurl string, args ...interface{}) (resp *Response, err error) {

	return req.Do(http.MethodGet, origurl, args...)

}

func (req *Request) Post(origurl string, args ...interface{}) (resp *Response, err error) {

	return req.Do(http.MethodPost, origurl, args...)

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

func (req *Request) RegisterCallback(callbacks ...Callback) {
	req.Callbacks = append(req.Callbacks, callbacks...)
}

func (req *Request) RequestDebug() {
	buf := new(bytes.Buffer)
	buf.WriteString(fmt.Sprintf("\n------------------- Request Info  ---------------------\n"))
	defer buf.WriteTo(req.Logger)
	message, err := httputil.DumpRequestOut(req.HttpRequest, false)
	if err != nil {
		buf.WriteString(fmt.Sprintf("ERROR:%v", err))
		return
	}
	buf.Write(message)
	if len(req.Client.Jar.Cookies(req.HttpRequest.URL)) > 0 {
		for _, cookie := range req.Client.Jar.Cookies(req.HttpRequest.URL) {
			buf.WriteString(fmt.Sprintf("%v=%v;", cookie.Name, cookie.Value))
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
		req.Client.Jar.SetCookies(req.HttpRequest.URL, req.Cookies)
		req.ClearCookies()
	}

}

// set timeout s = second
func (req *Request) SetTimeout(n time.Duration) {
	req.Client.Timeout = time.Duration(n * time.Second)
}

func (req *Request) Close() {
	req.HttpRequest.Close = true
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
	defer buf.WriteTo(resp.req.Logger)
	message, err := httputil.DumpResponse(resp.R, false)
	if err != nil {
		buf.WriteString(fmt.Sprintf("ERROR:%v\n", err))
		buf.WriteString(fmt.Sprintf("\n------------------- Request End  ---------------------\n"))
		return
	}
	buf.WriteString(fmt.Sprintf("\n------------------- Response Info  ---------------------\n"))
	buf.Write(message)
	buf.WriteString(fmt.Sprintf("\n------------------- Request End  ---------------------\n"))
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
			resp.req.writeLog(err)
			resp.req.writeLog(body)
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
	httpreq := resp.req.HttpRequest
	client := resp.req.Client

	cookies = client.Jar.Cookies(httpreq.URL)

	return cookies

}

/**************post*************************/
// call req.Post ,only for easy
func Post(origurl string, args ...interface{}) (resp *Response, err error) {
	req := Requests()

	// call request POST
	resp, err = req.Do(http.MethodPost, origurl, args...)
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
	req.Header.Set("Content-Type", "application/json")
	return req.Do("POST", origurl, args...)
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

func (req *Request) Do(method string, origurl string, args ...interface{}) (*Response, error) {

	var err error
	var res *http.Response
	var resp Response
	defer func() {
		for _, cb := range req.Callbacks {
			cb(req.HttpRequest.Context(), req.HttpRequest, res, err)
		}
	}()
	req.HttpRequest.Method = method

	//set default
	//req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// set params ?a=b&b=c
	//set Header
	params := []map[string]string{}
	datas := []map[string]string{} // POST
	files := []map[string]string{} //post file

	//reset Cookies,
	//Client.Do can copy cookie from client.Jar to req.Header
	delete(req.HttpRequest.Header, "Cookie")

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
		case Datas: //Post form data,packaged in reqBody.
			datas = append(datas, a)
		case Files:
			files = append(files, a)
		case Auth:
			// a{username,password}
			req.HttpRequest.SetBasicAuth(a[0], a[1])
		default:
			b := new(bytes.Buffer)
			err = json.NewEncoder(b).Encode(a)
			if err != nil {
				req.writeLog(err)
				return nil, err
			}
			req.setBodyRawBytes(ioutil.NopCloser(b))
		}
	}
	var disturl string
	disturl, err = buildURLParams(origurl, params...)
	if err != nil {
		req.writeLog(err)
		return nil, err
	}

	if len(files) > 0 {
		req.buildFilesAndForms(files, datas)

	} else {
		if len(datas) > 0 {
			Forms := req.buildForms(datas...)
			req.setBodyBytes(Forms) // set forms to reqBody
		}
	}
	//prepare to Do
	var URL *url.URL
	URL, err = url.Parse(disturl)
	if err != nil {
		req.writeLog(err)
		return nil, err
	}
	req.HttpRequest.URL = URL

	req.ClientSetCookies()

	req.RequestDebug()
	var reqBuffer bytes.Buffer

	var reqBody io.ReadCloser

	if len(req.Callbacks) > 0 && req.HttpRequest.Body != nil {

		_, err = reqBuffer.ReadFrom(req.HttpRequest.Body)
		if err != nil {
			return nil, err
		}
		req.HttpRequest.Body = ioutil.NopCloser(&reqBuffer)
		reqBody = io.NopCloser(bytes.NewReader(reqBuffer.Bytes()))

	}

	res, err = req.Client.Do(req.HttpRequest)

	if err != nil {
		req.writeLog(err)
		return nil, err
	}

	if len(req.Callbacks) > 0 && res.Body != nil {
		var resBuffer bytes.Buffer
		var respBody io.ReadCloser
		_, err = resBuffer.ReadFrom(res.Body)
		if err != nil {
			return nil, err
		}
		res.Body = ioutil.NopCloser(&resBuffer)
		respBody = io.NopCloser(bytes.NewReader(resBuffer.Bytes()))
		defer func() {
			res.Body = respBody
		}()
		req.HttpRequest.Body = reqBody
	}

	// clear post param
	req.HttpRequest.Body = nil
	req.HttpRequest.GetBody = nil
	req.HttpRequest.ContentLength = 0

	resp = Response{}
	resp.R = res
	resp.req = req

	resp.Content()
	defer res.Body.Close()

	resp.ResponseDebug()
	return &resp, nil
}

func (req *Request) writeLog(obj interface{}) {
	if req.Logger != nil {
		req.Logger.Write([]byte(fmt.Sprintf("%v", obj)))
	}
}

//func (req *Request) Post(origurl string, args ...interface{}) (resp *Response, err error) {
//
//	req.HttpRequest.Method = "POST"
//
//	//set default
//	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
//
//	// set params ?a=b&b=c
//	//set Header
//	var params []map[string]string
//	var datas []map[string]string // POST
//	var files []map[string]string //post file
//
//	//reset Cookies,
//	//Client.Do can copy cookie from client.Jar to req.Header
//	delete(req.HttpRequest.Header, "Cookie")
//
//	for _, arg := range args {
//		switch a := arg.(type) {
//		// arg is Header , set to request header
//		case Header:
//
//			for k, v := range a {
//				req.Header.Set(k, v)
//			}
//			// arg is "GET" params
//			// ?title=website&id=1860&from=login
//		case Params:
//			params = append(params, a)
//
//		case Datas: //Post form data,packaged in body.
//			datas = append(datas, a)
//		case Files:
//			files = append(files, a)
//		case Auth:
//			// a{username,password}
//			req.HttpRequest.SetBasicAuth(a[0], a[1])
//		}
//	}
//
//	disturl, _ := buildURLParams(origurl, params...)
//
//	if len(files) > 0 {
//		req.buildFilesAndForms(files, datas)
//
//	} else {
//		Forms := req.buildForms(datas...)
//		req.setBodyBytes(Forms) // set forms to body
//	}
//	//prepare to Do
//	URL, err := url.Parse(disturl)
//	if err != nil {
//		req.writeLog(err)
//		return nil, err
//	}
//	req.HttpRequest.URL = URL
//
//	req.ClientSetCookies()
//
//	req.RequestDebug()
//
//	res, err := req.Client.Do(req.HttpRequest)
//
//	// clear post param
//	req.HttpRequest.Body = nil
//	req.HttpRequest.GetBody = nil
//	req.HttpRequest.ContentLength = 0
//
//	if err != nil {
//		req.writeLog(err)
//		return nil, err
//	}
//
//	resp = &Response{}
//	resp.R = res
//	resp.req = req
//
//	resp.Content()
//	defer res.Body.Close()
//
//	resp.ResponseDebug()
//	return resp, nil
//}

// only set forms
func (req *Request) setBodyBytes(Forms url.Values) {

	// maybe
	data := Forms.Encode()
	req.HttpRequest.Body = ioutil.NopCloser(strings.NewReader(data))
	req.HttpRequest.ContentLength = int64(len(data))
}

// only set forms
func (req *Request) setBodyRawBytes(read io.ReadCloser) {
	req.HttpRequest.Body = read
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
	req.HttpRequest.Body = ioutil.NopCloser(bytes.NewReader(b.Bytes()))
	req.HttpRequest.ContentLength = int64(b.Len())
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
