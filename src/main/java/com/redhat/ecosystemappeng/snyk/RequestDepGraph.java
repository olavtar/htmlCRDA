package com.redhat.ecosystemappeng.snyk;

import java.util.ArrayList;

public class RequestDepGraph {
    public String schemaVersion;
    public RequestPkgManager pkgManager;
    public ArrayList<RequestPkg> pkgs;
    public RequestGraph graph;
}
