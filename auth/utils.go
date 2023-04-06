package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

func makeTimeFromString(st string) time.Time {
	start, end := st[:len(st)-1], st[len(st)-1:]
	startInt, _ := strconv.Atoi(start)

	switch end {
	case "d":
		return time.Now().Add(time.Duration(startInt) * 24 * time.Hour)
	case "h":
		return time.Now().Add(time.Duration(startInt) * time.Hour)
	case "m":
		return time.Now().Add(time.Duration(startInt) * time.Minute)
	case "s":
		return time.Now().Add(time.Duration(startInt) * time.Second)
	}

	return time.Now()
}

func makeResponse(w http.ResponseWriter, body any, err string, code int) {
	w.WriteHeader(code)
	if err != "" {
		json.NewEncoder(w).Encode(DefaultResponse{
			Error: &err,
			Body:  nil,
		})
		return
	}
	json.NewEncoder(w).Encode(DefaultResponse{
		Error: nil,
		Body:  body,
	})
}

func contentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
