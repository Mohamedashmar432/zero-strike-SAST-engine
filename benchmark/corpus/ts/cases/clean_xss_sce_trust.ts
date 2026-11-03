declare const $sce: any;

export function show($scope: any): void {
  $scope.banner = $sce.trustAsHtml('<b>Welcome</b>');
}
