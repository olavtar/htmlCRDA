<html>
<head>
    <#include "styles.ftlh">
<title>${title}</title>
</head>
<body>
<#--<h1>${title}</h1>-->

<#--<p>${exampleObject.name} by ${exampleObject.developer}</p>-->

<#--<ul>-->
<#--<#list systems as system>-->
<#--<li>${system_index + 1}. ${system.name} from ${system.developer}</li>-->
<#--</#list>-->
<#--</ul>-->

<script>
    function openTab(tabName) {
        var i, x;
        x = document.getElementsByClassName("containerTab");
        for (i = 0; i < x.length; i++) {
            x[i].style.display = "none";
        }
        document.getElementById(tabName).style.display = "block";
    }
</script>

<div class="row">
    <div class="column" onclick="openTab('b1');">
        <div class="card">
            <h3>${security.title}</h3>
            <p>${security.description}</p>
            <p>${security.totalVulnerabilities}        ${security.totalVulnerabilitiesCount}</p>
            <p>${security.vulnerableDependencies}      ${security.vulnerableDependenciesCount}</p>
        </div>
    </div>

    <div class="column" onclick="openTab('b2');">
        <div class="card">
            <h3>${security.title}</h3>
            <p>${security.description}</p>
            <p>${security.totalVulnerabilities}        ${security.totalVulnerabilitiesCount}</p>
            <p>${security.vulnerableDependencies}      ${security.vulnerableDependenciesCount}</p>
        </div>
    </div>

    <div class="column" onclick="openTab('b3');">
        <div class="card">
            <h3>Card 3</h3>
            <p>Some text</p>
            <p>Some text</p>
        </div>
    </div>

    <div class="column" onclick="openTab('b4');">
        <div class="card">
            <h3>Card 4</h3>
            <p>Some text</p>
            <p>Some text</p>
        </div>
    </div>
</div>

<!-- Full-width columns: (hidden by default) -->
<div id="b1" class="containerTab" style="display:none;background:green">
    <span onclick="this.parentElement.style.display='none'" class="closebtn">&times;</span>
    <h2>Box 1</h2>
    <p>Lorem ipsum dolor sit amet, te quo doctus abhorreant, et pri deleniti intellegat, te sanctus inermis ullamcorper nam. Ius error diceret deseruisse ad</p>
</div>

<div id="b2" class="containerTab" style="display:none;background:blue">
    <span onclick="this.parentElement.style.display='none'" class="closebtn">&times;</span>
    <h2>Box 2</h2>
    <p>Lorem ipsum dolor sit amet, te quo doctus abhorreant, et pri deleniti intellegat, te sanctus inermis ullamcorper nam. Ius error diceret deseruisse ad</p>
</div>

<div id="b3" class="containerTab" style="display:none;background:red">
    <span onclick="this.parentElement.style.display='none'" class="closebtn">&times;</span>
    <h2>Box 3</h2>
    <p>Lorem ipsum dolor sit amet, te quo doctus abhorreant, et pri deleniti intellegat, te sanctus inermis ullamcorper nam. Ius error diceret deseruisse ad</p>
</div>

<div id="b4" class="containerTab" style="display:none;background:yellowgreen">
    <span onclick="this.parentElement.style.display='none'" class="closebtn">&times;</span>
    <h2>Box 4</h2>
    <p>Lorem ipsum dolor sit amet, te quo doctus abhorreant, et pri deleniti intellegat, te sanctus inermis ullamcorper nam. Ius error diceret deseruisse ad</p>
</div>

</body>
</html>