# Installation


# example 1

```
package main

import "github.com/sjqzhang/requests"


func main (){

        resp,err := requests.Get("http://go.xiulian.net.cn")
        if err != nil {
          return 
        }
        println(resp.Text())
}

```
