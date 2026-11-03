// Trusting a constant string is not an injection.
angular.module('app').controller('BannerCtrl', function ($scope, $sce) {
  $scope.banner = $sce.trustAsHtml('<b>Welcome</b>');
});
