package main

import (
	"fmt"
	"github.com/sjqzhang/requests"
)

func main (){

	req := requests.Requests()

  resp,_ := req.Get("https://api.github.com/user",requests.Auth{"asmcos","password...."})
  println(resp.Text())
	fmt.Println(resp.R.StatusCode)
	fmt.Println(resp.R.Header["Content-Type"])
}
