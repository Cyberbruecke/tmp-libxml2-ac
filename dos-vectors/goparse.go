// goparse.go -- time Go's encoding/xml streaming decode of a payload file (namespace-aware).
// Parse-time cost only (encoding/xml is a streaming tokenizer, like expat). Internal timing.
// Usage: goparse <file.xml> [reps]  -> prints parse seconds.
package main
import ("encoding/xml";"fmt";"os";"strconv";"time";"bytes";"io")
func main(){
    data,_ := os.ReadFile(os.Args[1])
    reps := 1
    if len(os.Args) > 2 { reps,_ = strconv.Atoi(os.Args[2]) }
    t0 := time.Now()
    for i:=0; i<reps; i++ {
        d := xml.NewDecoder(bytes.NewReader(data))
        for {
            _, err := d.Token()
            if err == io.EOF { break }
            if err != nil { fmt.Println("REJECT:", err); return }
        }
    }
    fmt.Printf("%.6f\n", time.Since(t0).Seconds()/float64(reps))
}
