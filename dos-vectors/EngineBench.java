// EngineBench.java -- Java-DOM (Xerces) equivalents of FlAttr and Wreckoncile, to fill the
// cross-engine matrix. Internal timing (JVM startup excluded).
//   flattr N       : N x setAttributeNS on one element (the marshaller op)
//   import  FILE    : importNode(deep) of the parsed flood (Wreckoncile op)
import javax.xml.parsers.*; import org.w3c.dom.*; import java.io.File;
public class EngineBench {
  public static void main(String[] a) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); f.setNamespaceAware(true);
    try { f.setAttribute("http://apache.org/xml/properties/elementAttributeLimit", 0);} catch(Exception e){}
    DocumentBuilder b = f.newDocumentBuilder();
    if (a[0].equals("flattr")) {
      int N = Integer.parseInt(a[1]);
      Document doc = b.newDocument(); Element e = doc.createElement("e"); doc.appendChild(e);
      // warm
      Element w = doc.createElement("w"); for(int i=0;i<1000;i++) w.setAttributeNS("urn:x","p:a"+i,"");
      long t0=System.nanoTime();
      for(int i=0;i<N;i++) e.setAttributeNS("urn:x","p:a"+i,"");
      System.out.printf("%.6f%n",(System.nanoTime()-t0)/1e9);
    } else { // import
      Document src = b.parse(new File(a[1]));
      Node flood = src.getDocumentElement().getFirstChild();
      while (flood!=null && flood.getNodeType()!=Node.ELEMENT_NODE) flood=flood.getNextSibling();
      Document dst = b.newDocument(); dst.importNode(flood, true); // warm
      long t0=System.nanoTime();
      Document d2 = b.newDocument(); d2.importNode(flood, true);
      System.out.printf("%.6f%n",(System.nanoTime()-t0)/1e9);
    }
  }
}
