<html xmlns="http://www.w3.org/1999/html">
<head>
    <#include "snykstyles.ftlh">
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="fonts.css"/>
    <!-- Include latest PatternFly CSS via CDN -->
    <link
            rel="stylesheet"
            href="https://unpkg.com/@patternfly/patternfly/patternfly.css"
            crossorigin="anonymous"
    />
    <link rel="stylesheet" href="style.css"/>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/css/bootstrap.min.css"
          integrity="sha384-TX8t27EcRE3e/ihU7zmQxVncDAy5uIKz4rEkgIXeMed4M0jlfIDPvg6uqKI2xXr2" crossorigin="anonymous">
</head>
<body class="p-3">
< class="container-fluid">
    <div class="card bg-light">
        <div class="card-body ml-3">
            <h5 class="card-title">
                  <span class="pf-c-icon">
                  <i class="fa fa-shield-alt" aria-hidden="true"></i>
                  </span>
                ${securityTitle}
        </div>
        </h5>
        <p class="card-text ml-5">${securityDesc}</p>
        <p class="ml-5">Total Vulnerabilities: ${issues?size}</p>
        <p class="ml-5">Vulnerable Dependencies: ${mavenObject.countVulnerableDependencies()}</p>
    </div>

<div class="ml-3 mt-4">
    <h3 class="font-weight-light">${subTitle}</h3>
    <div class="pb-4">${subDescription}</div>
    <div class="d-inline p-2 bg-light">${insideHeader}</div>
</div>
<div>
    <hr class="pf-c-divider mt-2"/>
</div>
<#--<div class="p-3">-->
<#--    <table class="table" style="border-collapse:collapse; font-size: smaller;">-->
<#--        <thead>-->
<#--        <tr>-->
<#--            <th scope="col">#</th>-->
<#--            <th scope="col">Dependencies</th>-->
<#--            <th scope="col"># Direct</th>-->
<#--            <th scope="col"># Transitive</th>-->
<#--            <th scope="col">Highest CVSS</th>-->
<#--            <th scope="col">Highest Severity</th>-->
<#--&lt;#&ndash;            <th scope="col">Red Hat Recommendation</th>&ndash;&gt;-->
<#--            &lt;#&ndash;-->
<#--            <th scope="col"></th>-->
<#--            &ndash;&gt;-->
<#--        </tr>-->
<#--        </thead>-->
<#--        <tbody>-->
<#--        <#assign numOfPkg = 0>-->
<#--        <#list mavenObject.dependencies as mavenPackage>-->
<#--            <#if (mavenPackage.countDirectVulnerabilities() != 0 || mavenPackage.countTransitiveVulnerabilities() != 0) >-->
<#--                <tr data-toggle="collapse" data-target="#${mavenPackage.getHtmlName()}" class="accordion-toggle">-->
<#--                    <#assign numOfPkg++>-->
<#--                    <td>#${numOfPkg} <i class="fa fa-angle-down"></i></td>-->
<#--                    <td>${mavenPackage.pkgName}</td>-->
<#--                    <td>${mavenPackage.countDirectVulnerabilities()}</td>-->
<#--                    <td>${mavenPackage.countTransitiveVulnerabilities()}</td>-->
<#--                    <#if (mavenPackage.countDirectVulnerabilities() != 0) >-->
<#--                        <td>${mavenPackage.getHighestVulnerability().cvssScore}/10</td>-->
<#--                        <td>${mavenPackage.getHighestVulnerability().id}</td>-->
<#--                    <#else>-->
<#--                        <td>--</td>-->
<#--                        <td>--</td>-->
<#--                    </#if>-->
<#--&lt;#&ndash;                    <td>RH Rec goes here</td>&ndash;&gt;-->
<#--                    &lt;#&ndash;-->
<#--                    <td class="extra-small">&ndash;&gt;-->
<#--                    &lt;#&ndash;                            <span class="pf-c-icon">&ndash;&gt;-->
<#--                    &lt;#&ndash;                                <i class="fa fa-angle-down" aria-hidden="true"></i>&ndash;&gt;-->
<#--                    &lt;#&ndash;                            </span>&ndash;&gt;-->
<#--                    &lt;#&ndash;-->
<#--                 </td>-->
<#--                 &ndash;&gt;-->
<#--                </tr>-->
<#--                <tr>-->
<#--                    <td colspan="8" class="hiddenRow">-->
<#--                        <div class="accordian-body collapse py-4" id="${mavenPackage.getHtmlName()}">-->
<#--                            <p>Details of the dependency: <span class="font-weight-bold">${mavenPackage.pkgName}</span>-->
<#--                            </p>-->
<#--                            <#if (mavenPackage.vulnerabilities?size != 0) >-->
<#--                                <p>-->
<#--                                <li class="pf-u-font-weight-bold">Vulnerabilities:</li>-->
<#--                                <#list mavenPackage.vulnerabilities as vulnerability>-->
<#--                                    <ul class="pf-c-list">-->
<#--                                        <#if (vulnerability.severity == "high") >-->
<#--                                        <span class="pf-c-label pf-m-red">-->
<#--                            </#if><#if (vulnerability.severity == "medium") >-->
<#--                                <span class="pf-c-label pf-m-orange">-->
<#--                            </#if>-->
<#--                                    <#if (vulnerability.severity == "low") >-->
<#--                                <span class="pf-c-label pf-m-gold">-->
<#--                            </#if>-->
<#--                            <span class="pf-c-label__content">-->
<#--                                ${vulnerability.severity} - ${vulnerability.title} - ${vulnerability.cvssScore}-->
<#--                                    - ${vulnerability.id}-->
<#--                            </span>-->
<#--                                </span>-->
<#--                                    </ul>-->
<#--                                </#list>-->
<#--                                </p>-->
<#--                            </#if>-->
<#--                            <p>-->
<#--                            <li class="pf-u-font-weight-bold">Transitive Dependencies with vulnerabilites: </li></p>-->
<#--                            <div class="p-3">-->
<#--                            <table class="table" style="border-collapse:collapse; font-size: small;">-->
<#--                                <thead>-->
<#--                                <tr>-->
<#--                                    <th scope="col">#</th>-->
<#--                                    <th scope="col">Dependencies</th>-->
<#--                                    <th scope="col"># Direct</th>-->
<#--                                    <th scope="col"># Transitive</th>-->
<#--                                    <th scope="col">Highest CVSS</th>-->
<#--                                    <th scope="col">Highest Severity</th>-->
<#--                                </tr>-->
<#--                                </thead>-->
<#--                                <tbody>-->
<#--                                    <#list mavenPackage.getVulnerableTransitiveDeps() as transDependency>-->
<#--                                    <#assign barNum = transDependency.getHighestVulnerability().cvssScore *10>-->
<#--                                        <#assign numOfTransPkg = 0>-->
<#--                                    <#if (transDependency.countDirectVulnerabilities() != 0 ) >-->
<#--                                        <tr data-toggle="collapse" data-target="#${transDependency.getHtmlName()}" class="accordion-toggle py-4">-->
<#--                                            <#assign numOfTransPkg++>-->
<#--                                            <td>${transDependency?counter} <i class="fa fa-angle-down"></i></td>-->
<#--                                            <td>${transDependency.pkgName}</td>-->
<#--                                            <td>${transDependency.countDirectVulnerabilities()}</td>-->
<#--                                            <td>${transDependency.countTransitiveVulnerabilities()}</td>-->
<#--                                            <#if (transDependency.countDirectVulnerabilities() != 0) >-->
<#--                                                <td>${transDependency.getHighestVulnerability().cvssScore}/10</td>-->
<#--                                                <td>${transDependency.getHighestVulnerability().id}</td>-->
<#--                                            <#else>-->
<#--                                                <td>--</td>-->
<#--                                                <td>--</td>-->
<#--                                            </#if>-->
<#--                                        </tr>-->
<#--                                    <tr>-->
<#--                                        <td colspan="8" class="hiddenRow">-->
<#--                                            <div class="accordian-body collapse p-3" id="${transDependency.getHtmlName()}">-->
<#--                                                <p>Details of the dependency: <span class="font-weight-bold">${transDependency.pkgName}</span>-->
<#--                                                </p>-->
<#--                                                <#if (transDependency.vulnerabilities?size != 0) >-->
<#--                                                    <p>-->
<#--                                                    <li class="pf-u-font-weight-bold">Vulnerabilities:</li>-->
<#--                                                    <#list transDependency.vulnerabilities as vulnerability>-->
<#--                                                        <ul class="pf-c-list">-->
<#--                                                            <#if (vulnerability.severity == "high") >-->
<#--                                                            <span class="pf-c-label pf-m-red">-->
<#--                                                        </#if><#if (vulnerability.severity == "medium") >-->
<#--                                                            <span class="pf-c-label pf-m-orange">-->
<#--                                                        </#if>-->
<#--                                                                <#if (vulnerability.severity == "low") >-->
<#--                                                            <span class="pf-c-label pf-m-gold">-->
<#--                                                        </#if>-->
<#--                                                        <span class="pf-c-label__content">-->
<#--                                                            ${vulnerability.severity} - ${vulnerability.title} - ${vulnerability.cvssScore}-->
<#--                                                                - ${vulnerability.id}-->
<#--                                                        </span>-->
<#--                                                            </span>-->
<#--                                                                                    </ul>-->
<#--                                                                                </#list>-->
<#--                                                                                </p>-->
<#--                                                </#if>-->
<#--                                            </div>-->
<#--                                                </td>-->
<#--                                    </#if>-->
<#--                                    </#list>-->


<#--                                </tbody>-->
<#--                            </table>-->
<#--                            </div>-->
<#--                        </div>-->
<#--                    </td>-->
<#--                </tr>-->
<#--            </#if>-->
<#--        </#list>-->
<#--        </tbody>-->
<#--    </table>-->
<#--</div>-->

<#--New Table-->
    <div class="p-3">
        <table class="table" style="border-collapse:collapse; font-size: smaller;">
            <thead>
            <tr>
                <th scope="col">#</th>
                <th scope="col">Dependencies</th>
                <th scope="col"># Direct</th>
                <th scope="col"># Transitive</th>
                <th scope="col">Highest CVSS</th>
                <th scope="col">Highest Severity</th>
                <#--            <th scope="col">Red Hat Recommendation</th>-->
                <#--
                <th scope="col"></th>
                -->
            </tr>
            </thead>
            <tbody>
            <#assign numOfPkg = 0>
            <#list mavenObject.dependencies as mavenPackage>
                <#if (mavenPackage.countDirectVulnerabilities() != 0 || mavenPackage.countTransitiveVulnerabilities() != 0) >
                    <tr data-toggle="collapse" data-target="#${mavenPackage.getHtmlName()}" class="accordion-toggle">
                        <#assign numOfPkg++>
                        <td>#${numOfPkg} <i class="fa fa-angle-down"></i></td>
                        <td>${mavenPackage.pkgName}</td>
                        <td>${mavenPackage.countDirectVulnerabilities()}</td>
                        <td>${mavenPackage.countTransitiveVulnerabilities()}</td>
                        <#if (mavenPackage.countDirectVulnerabilities() != 0) >
                            <td>${mavenPackage.getHighestVulnerability().cvssScore}/10</td>
                            <td>${mavenPackage.getHighestVulnerability().id}</td>
                        <#else>
                            <td>--</td>
                            <td>--</td>
                        </#if>
                        <#--                    <td>RH Rec goes here</td>-->
                        <#--
                        <td class="extra-small">-->
                        <#--                            <span class="pf-c-icon">-->
                        <#--                                <i class="fa fa-angle-down" aria-hidden="true"></i>-->
                        <#--                            </span>-->
                        <#--
                     </td>
                     -->
                    </tr>
                    <tr>
                        <td colspan="8" class="hiddenRow">
                            <div class="accordian-body collapse py-4" id="${mavenPackage.getHtmlName()}">
                                <p>Details of the dependency: <span class="font-weight-bold">${mavenPackage.pkgName}</span>
                                </p>
                                <#if (mavenPackage.vulnerabilities?size != 0) >
                                    <p>
                                    <li class="pf-u-font-weight-bold">Vulnerabilities:</li>
                                    <#list mavenPackage.vulnerabilities as vulnerability>
                                        <ul class="pf-c-list">
                                            <#if (vulnerability.severity == "high") >
                                            <span class="pf-c-label pf-m-red">
                            </#if><#if (vulnerability.severity == "medium") >
                                <span class="pf-c-label pf-m-orange">
                            </#if>
                                    <#if (vulnerability.severity == "low") >
                                <span class="pf-c-label pf-m-gold">
                            </#if>
                            <span class="pf-c-label__content">
                                ${vulnerability.severity} - ${vulnerability.title} - ${vulnerability.cvssScore}
                                    - ${vulnerability.id}
                            </span>
                                </span>
                                        </ul>
                                    </#list>
                                    </p>
                                </#if>
                                <p>
                                <li class="pf-u-font-weight-bold">Transitive Dependencies with vulnerabilites: </li></p>
                                <div class="p-3">
                                    <table class="table" style="border-collapse:collapse; font-size: small;">
                                        <thead>
                                        <tr>
                                            <th scope="col">Dependencies</th>
                                            <th scope="col">Severity</th>
                                            <th scope="col">Description</th>
                                            <th scope="col">CVSS</th>
                                            <th scope="col">Snyk ID</th>
                                            <th scope="col">Red Hat remediation</th>
                                        </tr>
                                        </thead>
                                        <tbody>
                                        <#list mavenPackage.getVulnerableTransitiveDeps() as transDependency>
                                        <#assign barNum = transDependency.getHighestVulnerability().cvssScore *10>
                                        <#if (transDependency.countDirectVulnerabilities() != 0 ) >
                                            <#assign numOfVul = transDependency.vulnerabilities?size/>
                                            <#list transDependency.vulnerabilities as vulnerability>
                                                <#if vulnerability?index == 0>
                                            <tr >
                                                <td rowspan="${numOfVul}">${transDependency.pkgName}</td>
                                                <td>${vulnerability.severity}</td>
                                                <td>${vulnerability.title}</td>
                                                <td>${vulnerability.cvssScore}</td>
                                                <td>${vulnerability.id}</td>
                                                <td>RH Remediation</td>
                                            </tr>
                                                <#else >
                                                <tr >
                                                    <td>${vulnerability.severity}</td>
                                                    <td>${vulnerability.title}</td>
                                                    <td>${vulnerability.cvssScore}</td>
                                                    <td>${vulnerability.id}</td>
                                                    <td>RH Remediation</td>

                                                </tr>
                                                </#if>

                                            </#list>
                                        </#if>
                                        </#list>


                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </td>
                    </tr>
                </#if>
            </#list>
            </tbody>
        </table>
    </div>


</div>
<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"
        integrity="sha384-DfXdz2htPH0lsSSs5nCTpuj/zy4C+OGpamoFVy38MVBnE+IbbVYUew+OrCXaRkfj"
        crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-ho+j7jyWK8fNQe+A12Hb8AhRq26LrZ/JpcUGGOn+Y7RsweNrtN/tE3MoK7ZeZDyx"
        crossorigin="anonymous"></script>
</body>
</html>