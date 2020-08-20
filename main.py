import angr

from analysis.variable_propagation_analysis import SystemTableAnalysis


def main():
    proj = angr.Project('')
    angr.AnalysesHub.register_default('SystemTableAnalysis', SystemTableAnalysis)
    proj.analyses.SystemTableAnalysis()


if __name__ == '__main__':
    main()
