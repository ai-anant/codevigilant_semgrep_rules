import hudson.util.FormValidation;
import org.kohsuke.stapler.QueryParameter;
import java.io.File;

public class CheckFileExistsPos {
    public FormValidation doCheckPath(@QueryParameter String value) {
        if (value == null || value.trim().equals("")) {
            return FormValidation.warning("No path specified.");
        }
        File ftmp = new File(value);
        if (!ftmp.exists())
            return FormValidation.error("Specified path not found.");
        if (ftmp.isFile())
            return FormValidation.error("You specified a file but not a path.");
        return FormValidation.ok();
    }
}
