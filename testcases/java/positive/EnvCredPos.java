import hudson.EnvVars;

public class EnvCredPos {
    public void run(Object build, Object listener, Object launcher) throws Exception {
        hudson.EnvVars envVars = ((hudson.model.Run<?, ?>) build).getEnvironment((hudson.model.TaskListener) listener);
        if (!getDescriptor().getUser().trim().isEmpty() && !getDescriptor().getPassword().trim().isEmpty()) {
            envVars.put("A3_SERVER_USER", getDescriptor().getUser());
            envVars.put("A3_SERVER_PASSWORD", getDescriptor().getPassword());
        }
    }

    public Object getDescriptor() { return new Object() {
        public String getPassword() { return "secret"; }
        public String getUser() { return "user"; }
    }; }
}
