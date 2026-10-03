// XercesBench.java -- time Apache Xerces-J parsing of a payload file, JVM startup excluded.
// Usage: java -cp .:/usr/share/java/xercesImpl.jar \
//          -Djavax.xml.parsers.DocumentBuilderFactory=org.apache.xerces.jaxp.DocumentBuilderFactoryImpl \
//          XercesBench <file.xml> [reps]
// Prints one line: "parse_seconds". Limits are raised so we measure the raw O() curve;
// Xerces' DEFAULT secure-processing caps (elementAttributeLimit=10000, entityExpansion)
// are a mitigation and are reported separately in the benchmark notes.
import java.io.File;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class XercesBench {
    public static void main(String[] args) throws Exception {
        String file = args[0];
        int reps = args.length > 1 ? Integer.parseInt(args[1]) : 1;
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);            // exercise the SymbolTable / namespace binder
        // Raise the defensive caps so the cost curve is visible (see notes).
        try { f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false); } catch (Exception e) {}
        try { f.setAttribute("http://apache.org/xml/properties/elementAttributeLimit", 0); } catch (Exception e) {}
        try { f.setAttribute("http://www.oracle.com/xml/jaxp/properties/entityExpansionLimit", 0); } catch (Exception e) {}
        // warm up the JIT once (not timed)
        DocumentBuilder b = f.newDocumentBuilder();
        b.parse(new File(file));
        long t0 = System.nanoTime();
        for (int i = 0; i < reps; i++) {
            DocumentBuilder db = f.newDocumentBuilder();
            Document d = db.parse(new File(file));
        }
        double sec = (System.nanoTime() - t0) / 1e9 / reps;
        System.out.printf("%.6f%n", sec);
    }
}
