import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.Cpg
import java.io.PrintWriter
import java.io.File

@main def exec(cpgPath: String, outPath: String) = {
  // 1. 컴파일된 이진 CPG 그래프 데이터 로드
  val cpg = Cpg.load(cpgPath)

  // 2. CWE-89 (SQL Injection) 데이터 추적: 외부 입력(Source)이 위험 함수(Sink)에 도달하는지 연산
  val phpSources = cpg.identifier.name(".*_GET.*").toSet ++ cpg.identifier.name(".*_POST.*").toSet
  val phpSinks = cpg.call("mysqli_query").argument(2)
  val isPhpVuln = phpSinks.reachableBy(phpSources.iterator).nonEmpty

  // 3. CWE-119 (Buffer Overflow) 데이터 추적: C언어 strcpy 취약 지점 연산
  val cSources = cpg.call("getenv").toSet ++ cpg.identifier.name(".*input.*").toSet
  val cSinks = cpg.call("strcpy").argument(1)
  val isCVuln = cSinks.reachableBy(cSources.iterator).nonEmpty

  // 4. 분석 결과 데이터를 구조화된 텍스트로 가공
  val hasVuln = isPhpVuln || isCVuln
  val matchedCve = if (isPhpVuln) "CWE-89 (SQL Injection)" else if (isCVuln) "CWE-119 (Buffer Overflow Risk)" else "N/A"
  
  // 5. 파이썬 엔진이 읽어갈 수 있도록 중간 분석 리포트 파일로 물리적 저장
  val writer = new PrintWriter(new File(outPath))
  writer.write(hasVuln.toString + "|" + matchedCve)
  writer.close()
}