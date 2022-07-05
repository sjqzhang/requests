package main

import "github.com/sjqzhang/requests"


func main (){

        resp,_ := requests.Get("http://www.baidu.com")
        println(resp.Text())
}
