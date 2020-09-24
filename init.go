package  obscrypt

func init() {
	initonce.Do(initCurves)
}
