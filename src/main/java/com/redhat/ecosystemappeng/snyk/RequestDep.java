package com.redhat.ecosystemappeng.snyk;

public class RequestDep {
    public String nodeId;

    public String getNodeId() {
        return nodeId;
    }

    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }

    @Override
    public String toString() {
        return "RequestDep{" +
                "nodeId='" + nodeId + '\'' +
                '}';
    }

}
