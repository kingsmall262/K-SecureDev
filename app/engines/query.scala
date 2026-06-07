import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.Cpg
import java.io.PrintWriter
import java.io.File

@main def exec(cpgPath: String, outPath: String) = {
  // 1. 컴파일된 이진 CPG 그래프 로드
  val cpg = Cpg.load(cpgPath)

  // 2. PHP SQL 인젝션 소스 및 싱크 상세 추적
  val phpSources = cpg.identifier.name(".*_GET.*").toSet ++ cpg.identifier.name(".*_POST.*").toSet
  val phpSinks = cpg.call("mysqli_query").argument(2)
  val phpFlows = phpSinks.reachableBy(phpSources.iterator).flows.toList

  // 3. C언어 버퍼 오버플로우 소스 및 싱크 상세 추적
  val cSources = cpg.call("getenv").toSet ++ cpg.identifier.name(".*input.*").toSet
  val cSinks = cpg.call("strcpy").argument(1)
  val cFlows = cSinks.reachableBy(cSources.iterator).flows.toList

  // 4. PHP XSS 소스 및 싱크 상세 추적 (CWE-79)
  val phpXssSinks = cpg.call("echo").argument(1)
  val phpXssFlows = phpXssSinks.reachableBy(phpSources.iterator).flows.toList

  // 5. Python Path Traversal 소스 및 싱크 상세 추적 (CWE-22)
  val pySources = cpg.call("input").toSet ++ cpg.identifier.name(".*input.*").toSet
  val pyPathSinks = cpg.call("open").argument(1)
  val pyPathFlows = pyPathSinks.reachableBy(pySources.iterator).flows.toList

  // 6. Python Command Injection 소스 및 싱크 상세 추적 (CWE-78)
  val pyCmdSinks = cpg.call("system").argument(1)
  val pyCmdFlows = pyCmdSinks.reachableBy(pySources.iterator).flows.toList

  val writer = new PrintWriter(new File(outPath))

  // 7. 데이터 흐름 그래프 요소를 파싱하여 정확한 파일 주소 및 라인 넘버 적출
  if (phpFlows.nonEmpty) {
    val firstFlow = phpFlows.head
    val srcNode = firstFlow.elements.head
    val lineNumber = srcNode.lineNumber.getOrElse(0).toString
    val variableName = srcNode.code
    writer.write("true|CWE-89 (SQL Injection)|" + lineNumber + "|" + variableName)
  } else if (cFlows.nonEmpty) {
    val firstFlow = cFlows.head
    val srcNode = firstFlow.elements.head
    val lineNumber = srcNode.lineNumber.getOrElse(0).toString
    val variableName = srcNode.code
    writer.write("true|CWE-119 (Buffer Overflow Risk)|" + lineNumber + "|" + variableName)
  } else if (phpXssFlows.nonEmpty) {
    val firstFlow = phpXssFlows.head
    val srcNode = firstFlow.elements.head
    val lineNumber = srcNode.lineNumber.getOrElse(0).toString
    val variableName = srcNode.code
    writer.write("true|CWE-79 (Cross-Site Scripting)|" + lineNumber + "|" + variableName)
  } else if (pyPathFlows.nonEmpty) {
    val firstFlow = pyPathFlows.head
    val srcNode = firstFlow.elements.head
    val lineNumber = srcNode.lineNumber.getOrElse(0).toString
    val variableName = srcNode.code
    writer.write("true|CWE-22 (Path Traversal)|" + lineNumber + "|" + variableName)
  } else if (pyCmdFlows.nonEmpty) {
    val firstFlow = pyCmdFlows.head
    val srcNode = firstFlow.elements.head
    val lineNumber = srcNode.lineNumber.getOrElse(0).toString
    val variableName = srcNode.code
    writer.write("true|CWE-78 (OS Command Injection)|" + lineNumber + "|" + variableName)
  } else {
    writer.write("false|N/A|0|none")
  }
  
  writer.close()
}