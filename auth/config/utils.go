package config

import (
	"fmt"
	"strconv"
)

func validateStringTime(st string) error {
	start, end := st[:len(st)-1], st[len(st)-1:]
	var validEnd bool
	switch end {
	case "d", "h", "m", "s":
		validEnd = true
	}

	if !validEnd {
		return fmt.Errorf("not valid unit %q. Expected d, h, m, s", end)
	}

	startInt, err := strconv.Atoi(start)
	if err != nil {
		return err
	}

	if startInt == 0 {
		return fmt.Errorf("not valid quantity of time. Got %q, Expected number greater than 0", start)
	}

	return nil
}
