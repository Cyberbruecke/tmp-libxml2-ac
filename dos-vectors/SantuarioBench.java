// SantuarioBench.java -- time Apache Santuario (org.apache.xml.security) canonicalization,
// the DSig/C14N engine behind OpenSAML/Shibboleth. Parse is excluded (done once, untimed);
// we time canonicalizeSubtree over the flood, the operation a signature verify runs.
// Usage: java -cp <santuario-cp> SantuarioBench <file.xml> <inc|exc> [reps]  -> prints c14n seconds.
import java.io.File;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.signature.XMLSignatureInput;

public class SantuarioBench {
    static final java.io.OutputStream SINK = new java.io.OutputStream() {
        public void write(int b) {} public void write(byte[] b, int o, int l) {} };
    static final String XPATH_EXPR = "count(preceding-sibling::a) > 0";

    public static void main(String[] a) throws Exception {
        String file = a[0], mode = a[1];
        int reps = a.length > 2 ? Integer.parseInt(a[2]) : 1;
        Init.init();
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        Document doc = f.newDocumentBuilder().parse(new File(file));

        Runnable op;
        if (mode.equals("xpath")) {
            // DSig XPath Filter transform: predicate evaluated per node in the input node-set.
            op = () -> {
                try {
                    Transforms t = new Transforms(doc);
                    Element xp = doc.createElementNS("http://www.w3.org/2000/09/xmldsig#", "ds:XPath");
                    xp.appendChild(doc.createTextNode(XPATH_EXPR));
                    t.addTransform(Transforms.TRANSFORM_XPATH, xp);
                    XMLSignatureInput in = new XMLSignatureInput(doc.getDocumentElement());
                    t.performTransforms(in).getBytes();
                } catch (Exception e) { throw new RuntimeException(e); }
            };
        } else {
            String algo = mode.equals("exc")
                ? Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
                : Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS;
            Canonicalizer c = Canonicalizer.getInstance(algo);
            op = () -> { try { c.canonicalizeSubtree(doc.getDocumentElement(), SINK); }
                         catch (Exception e) { throw new RuntimeException(e); } };
        }
        op.run();                                            // warm up
        long t0 = System.nanoTime();
        for (int i = 0; i < reps; i++) op.run();
        System.out.printf("%.6f%n", (System.nanoTime() - t0) / 1e9 / reps);
    }
}
