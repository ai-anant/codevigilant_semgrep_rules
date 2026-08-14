import hudson.util.FormValidation;
import java.io.File;

public class CapabilityPos {
    public FormValidation doCheckDax_file(String value) {
        File ftmp = new File(value);
        if (!ftmp.exists())
            return FormValidation.error("Specified file not found.");
        if (!ftmp.canRead())
            return FormValidation.error("Specified file cannot be read.");
        if (!ftmp.isFile())
            return FormValidation.error("Specified path is no file.");
        if (!ftmp.canExecute())
            return FormValidation.error("Specified file cannot be executed.");
        return FormValidation.ok();
    }
}
