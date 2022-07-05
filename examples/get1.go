package main

import "github.com/sjqzhang/requests"


func main (){

        resp,_ := requests.Get("http://go.xiulian.net.cn")
        println(resp.Text())
}
