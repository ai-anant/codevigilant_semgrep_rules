import hudson.util.FormValidation;
import java.io.File;

public class CapabilityNeg {
    public FormValidation doCheckPath(String value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        File ftmp = new File(value);
        if (!ftmp.canRead())
            return FormValidation.error("cannot read");
        if (!ftmp.isFile())
            return FormValidation.error("not a file");
        return FormValidation.ok();
    }

    public FormValidation doCheckOther(String value) {
        return FormValidation.ok();
    }
}
