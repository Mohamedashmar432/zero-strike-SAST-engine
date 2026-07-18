import org.yaml.snakeyaml.Yaml;

public class VulnSnakeyamlLoad {
    Object parse(String document) {
        Yaml yaml = new Yaml();
        // ZS-JAVA-029: SnakeYAML load() without SafeConstructor — arbitrary type construction
        return yaml.load(document);
    }
}
