import javax.servlet.http.HttpServletRequest;
import org.springframework.expression.ExpressionParser;

public class VulnSpelInjection {
    void handle(HttpServletRequest request, ExpressionParser parser) {
        String expr = request.getParameter("expr");
        // ZS-JAVA-034: SpEL injection — attacker-controlled expression is evaluated
        parser.parseExpression(expr);
    }
}
