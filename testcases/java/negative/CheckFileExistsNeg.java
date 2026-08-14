import hudson.util.FormValidation;
import org.kohsuke.stapler.QueryParameter;
import java.io.File;

public class CheckFileExistsNeg {
    public FormValidation doCheckPath(@QueryParameter String value) {
        if (value == null || value.trim().equals("")) {
            return FormValidation.warning("No path specified.");
        }
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        File ftmp = new File(value);
        if (!ftmp.exists())
            return FormValidation.error("Specified path not found.");
        return FormValidation.ok();
    }

    // Not a doCheck* handler - must not fire
    public FormValidation checkSomethingElse(@QueryParameter String value) {
        File ftmp = new File(value);
        if (!ftmp.exists())
            return FormValidation.error("not found");
        return FormValidation.ok();
    }
}
