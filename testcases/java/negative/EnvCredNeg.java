import hudson.EnvVars;

public class EnvCredNeg {
    public void run(Object build, Object listener) throws Exception {
        hudson.EnvVars envVars = ((hudson.model.Run<?, ?>) build).getEnvironment((hudson.model.TaskListener) listener);
        envVars.put("PATH", System.getenv("PATH"));
        envVars.put("TMP", "/tmp");
    }
}
