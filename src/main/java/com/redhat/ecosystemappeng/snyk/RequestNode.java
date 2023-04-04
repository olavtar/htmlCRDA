package com.redhat.ecosystemappeng.snyk;

import java.util.ArrayList;

public class RequestNode {

    public String nodeId;
    public String pkgId;
    public ArrayList<RequestDep> deps;

    @Override
    public String toString() {
        return "RequestNode{" +
                "nodeId='" + nodeId + '\'' +
                ", pkgId='" + pkgId + '\'' +
                ", deps=" + deps +
                '}';
    }

    public String getNodeId() {
        return nodeId;
    }

    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }

    public String getPkgId() {
        return pkgId;
    }

    public void setPkgId(String pkgId) {
        this.pkgId = pkgId;
    }

    public ArrayList<RequestDep> getDeps() {
        return deps;
    }

    public void setDeps(ArrayList<RequestDep> deps) {
        this.deps = deps;
    }
}
