import javax.servlet.http.HttpServletRequest;

// ZS-JAVA-012 (Runtime.exec) negative fixture.
//
// The rule asked only for "tainted_argument: true", which is satisfied by a
// tainted identifier anywhere in the call's subtree. Runtime.exec's command is
// always its first argument; the later overload parameters are the child's
// environment (String[] envp) and nothing that is parsed as a command line.
// Both calls below hard-code the command and put the request-derived value in
// an envp entry, and both were reported as CWE-78 command injection.
class SafeCmdiJava {

    String listFilesWithUserLocale(HttpServletRequest request) throws Exception {
        String locale = request.getParameter("locale");
        String[] env = {"LANG=" + locale};
        // Argument 0 is a constant command. A tainted environment variable is
        // passed to the child as data, never interpreted as a command line.
        Process p = Runtime.getRuntime().exec("/bin/ls -la", env);
        return String.valueOf(p.waitFor());
    }

    String convertWithUserTempDir(HttpServletRequest request) throws Exception {
        String tmp = request.getParameter("tmp");
        String[] env = {"TMPDIR=" + tmp};
        String[] command = {"/usr/bin/convert", "in.png", "out.png"};
        // The cmdarray overload: argument 0 is still the command, and it is
        // built entirely from string literals.
        Process p = Runtime.getRuntime().exec(command, env);
        return String.valueOf(p.waitFor());
    }
}
