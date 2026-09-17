package backend.demo.repositories;
import backend.demo.entities.AnalysisReport;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AnalysisReportRepository extends JpaRepository<AnalysisReport, String> {

    // 1. Fetch report by alternative hashes
    Optional<AnalysisReport> findByMd5(String md5);
    Optional<AnalysisReport> findBySha1(String sha1);

    // 2. Fetch all malicious or suspicious detections
    List<AnalysisReport> findByThreatLevel(String threatLevel);

    // 3. Find high-risk scans exceeding a threat threshold
    List<AnalysisReport> findByThreatScoreGreaterThanEqual(int minScore);

    // 4. Custom query to search records matching a specific YARA rule match
    @Query("SELECT a FROM AnalysisReport a JOIN a.matchedYaraRules rule WHERE rule = :ruleName")
    List<AnalysisReport> findByMatchedYaraRule(@Param("ruleName") String ruleName);
}