import angr

from analysis.variable_propagation_analysis import SystemTableAnalysis
from analysis.smi_vuln_analysis import SmiVulnerabilitiesAnalysis


def main():
    proj = angr.Project('')
    angr.AnalysesHub.register_default('SystemTableAnalysis', SystemTableAnalysis)
    angr.AnalysesHub.register_default('SmiVulnerabilitiesAnalysis', SmiVulnerabilitiesAnalysis)

    proj.analyses.SmiVulnerabilitiesAnalysis(0x1337, 'env.yaml', 'header.h')
    proj.analyses.SystemTableAnalysis('header.h')


if __name__ == '__main__':
    main()
