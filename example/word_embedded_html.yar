import "zip"

rule embedded_html
{
    meta:
        author = "@stoerchl"
        info = "searches for a given string inside a zip file"
      
    condition:
        zip.has_string("word/document.xml", "wp15:webVideoPr") > 0

}
