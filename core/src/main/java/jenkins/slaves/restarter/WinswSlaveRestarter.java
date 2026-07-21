package jenkins.slaves.restarter;

import static java.util.logging.Level.FINE;
import static org.apache.commons.io.IOUtils.copy;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

/**
 * With winsw, restart via winsw
 */
@Extension
public class WinswSlaveRestarter extends SlaveRestarter {
    private transient String exe;

    @Override
    public boolean canWork() {
        try {
            exe = System.getenv("WINSW_EXECUTABLE");
            if (exe == null)
                return false;   // not under winsw

            return exec("status") == 0;
        } catch (InterruptedException | IOException e) {
            LOGGER.log(FINE, getClass() + " unsuitable", e);
            return false;
        }
    }

    /**
     * Validates that the given executable path is an absolute path pointing to
     * an existing regular file, preventing command injection via a maliciously
     * crafted WINSW_EXECUTABLE environment variable value.
     */
    private static Path validateExecutable(String executablePath) throws IOException {
        Path path;
        try {
            path = Paths.get(executablePath);
        } catch (InvalidPathException e) {
            throw new IOException("Invalid executable path: " + executablePath, e);
        }
        if (!path.isAbsolute()) {
            throw new IOException("Executable path must be absolute: " + executablePath);
        }
        if (!Files.isRegularFile(path)) {
            throw new IOException("Executable path does not point to a regular file: " + executablePath);
        }
        return path;
    }

    @SuppressFBWarnings(value = "COMMAND_INJECTION", justification = "exe is validated to be an absolute path to an existing regular file before use")
    private int exec(String cmd) throws InterruptedException, IOException {
        validateExecutable(exe);
        ProcessBuilder pb = new ProcessBuilder(exe, cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().close();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        copy(p.getInputStream(), baos);
        int r = p.waitFor();
        if (r != 0)
            LOGGER.info(exe + " cmd: output:\n" + baos);
        return r;
    }

    @Override
    public void restart() throws Exception {
        // winsw 1.16 supports this operation. this file gets updated via windows-slaves-plugin,
        // so it's possible that we end up in the situation where jenkins-slave.exe doesn't support
        // this command. If that is the case, there's nothing we can do about it.
        int r = exec("restart!");
        throw new IOException("Restart failure. '" + exe + " restart' completed with " + r + " but I'm still alive!  "
                               + "See https://www.jenkins.io/redirect/troubleshooting/windows-agent-restart"
                               + " for a possible explanation and solution");
    }

    private static final Logger LOGGER = Logger.getLogger(WinswSlaveRestarter.class.getName());

    private static final long serialVersionUID = 1L;
}
